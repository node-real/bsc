package epochmeta

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const (
	AccountMetadataPath = "m"
)

type BranchNodeEpochMeta struct {
	EpochMap [16]types.StateEpoch
}

func NewBranchNodeEpochMeta(epochMap [16]types.StateEpoch) *BranchNodeEpochMeta {
	return &BranchNodeEpochMeta{EpochMap: epochMap}
}

func (n *BranchNodeEpochMeta) Encode(w rlp.EncoderBuffer) {
	offset := w.List()
	for _, e := range n.EpochMap {
		w.WriteUint64(uint64(e))
	}
	w.ListEnd(offset)
}

func DecodeFullNodeEpochMeta(enc []byte) (*BranchNodeEpochMeta, error) {
	var n BranchNodeEpochMeta

	if err := rlp.DecodeBytes(enc, &n.EpochMap); err != nil {
		return nil, err
	}

	return &n, nil
}

// TODO(0xbundler): modify it as reader
type Storage interface {
	Get(addr common.Hash, path string) ([]byte, error)
	Delete(addr common.Hash, path string) error
	Put(addr common.Hash, path string, val []byte) error
	Commit(number *big.Int, blockRoot common.Hash) error
}

type StorageRW struct {
	snap    snapshot
	tree    *SnapshotTree
	dirties map[common.Hash]map[string][]byte

	stale bool
	lock  sync.RWMutex
}

// NewEpochMetaDatabase first find snap by blockRoot, if got nil, try using number to instance a read only storage
func NewEpochMetaDatabase(tree *SnapshotTree, number *big.Int, blockRoot common.Hash) (Storage, error) {
	snap := tree.Snapshot(blockRoot)
	if snap == nil {
		// try using default snap
		if snap = tree.Snapshot(types.EmptyRootHash); snap == nil {
			return nil, fmt.Errorf("cannot find target epoch layer %#x", blockRoot)
		}
		log.Debug("NewEpochMetaDatabase use default database", "number", number, "root", blockRoot)
	}
	return &StorageRW{
		snap:    snap,
		tree:    tree,
		dirties: make(map[common.Hash]map[string][]byte),
	}, nil
}

func (s *StorageRW) Get(addr common.Hash, path string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	// TODO(0xbundler): remove cache
	sub, exist := s.dirties[addr]
	if exist {
		if val, ok := sub[path]; ok {
			return val, nil
		}
	}

	// TODO(0xbundler): metrics hit count
	return s.snap.EpochMeta(addr, path)
}

func (s *StorageRW) Delete(addr common.Hash, path string) error {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if s.stale {
		return errors.New("storage has staled")
	}
	_, ok := s.dirties[addr]
	if !ok {
		s.dirties[addr] = make(map[string][]byte)
	}

	s.dirties[addr][path] = nil
	return nil
}

func (s *StorageRW) Put(addr common.Hash, path string, val []byte) error {
	prev, err := s.Get(addr, path)
	if err != nil {
		return err
	}
	if bytes.Equal(prev, val) {
		return nil
	}

	s.lock.RLock()
	defer s.lock.RUnlock()
	if s.stale {
		return errors.New("storage has staled")
	}

	_, ok := s.dirties[addr]
	if !ok {
		s.dirties[addr] = make(map[string][]byte)
	}
	s.dirties[addr][path] = val
	return nil
}

// Commit if you commit to an unknown parent, like deeper than 128 layers, will get error
func (s *StorageRW) Commit(number *big.Int, blockRoot common.Hash) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.stale {
		return errors.New("storage has staled")
	}

	s.stale = true
	err := s.tree.Update(s.snap.Root(), number, blockRoot, s.dirties)
	if err != nil {
		return err
	}

	return s.tree.Cap(blockRoot)
}
