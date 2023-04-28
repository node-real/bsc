package trie

import (
	"bytes"
	"errors"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type shadowExtensionNode struct {
	ShadowHash common.Hash
	Epoch      types.StateEpoch
}

func NewShadowExtensionNode(hash common.Hash, epoch types.StateEpoch) shadowExtensionNode {
	return shadowExtensionNode{
		ShadowHash: hash,
		Epoch:      epoch,
	}
}

type shadowBranchNode struct {
	ShadowHash common.Hash
	EpochMap   [16]types.StateEpoch
}

func NewShadowBranchNode(hash common.Hash, epochMap [16]types.StateEpoch) shadowBranchNode {
	return shadowBranchNode{hash, epochMap}
}

type ShadowNodeStorage interface {
	// Get key is the shadow node prefix path
	Get(path string) ([]byte, error)
	Put(path string, val []byte) error
	Delete(path string) error
}

type shadowNodeStorage4Trie struct {
	addr common.Hash
	rw   *ShadowNodeStorageRW
}

func NewShadowNodeStorage4Trie(addr common.Hash, rw *ShadowNodeStorageRW) ShadowNodeStorage {
	return &shadowNodeStorage4Trie{
		addr: addr,
		rw:   rw,
	}
}

func (s *shadowNodeStorage4Trie) Get(path string) ([]byte, error) {
	return s.rw.Get(s.addr, path)
}

func (s *shadowNodeStorage4Trie) Put(path string, val []byte) error {
	return s.rw.Put(s.addr, path, val)
}

func (s *shadowNodeStorage4Trie) Delete(path string) error {
	return s.rw.Delete(s.addr, path)
}

type ShadowNodeStorageRW struct {
	snap    shadowNodeSnapshot
	tree    *ShadowNodeSnapTree
	dirties map[common.Hash]map[string][]byte

	stale bool
	lock  sync.RWMutex
}

func NewShadowNodeStorageRW(tree *ShadowNodeSnapTree, blockRoot common.Hash) (*ShadowNodeStorageRW, error) {
	snap := tree.Snapshot(blockRoot)
	if snap == nil {
		// try using default snap
		if snap = tree.Snapshot(emptyRoot); snap == nil {
			return nil, errors.New("cannot find the snap")
		}
	}
	return &ShadowNodeStorageRW{
		snap:    snap,
		tree:    tree,
		dirties: make(map[common.Hash]map[string][]byte),
	}, nil
}

func (s *ShadowNodeStorageRW) Get(addr common.Hash, path string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if s.stale {
		return nil, errors.New("storage has staled")
	}
	sub, exist := s.dirties[addr]
	if exist {
		if val, ok := sub[path]; ok {
			return val, nil
		}
	}

	return s.snap.ShadowNode(addr, path)
}

func (s *ShadowNodeStorageRW) Delete(addr common.Hash, path string) error {
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

func (s *ShadowNodeStorageRW) Put(addr common.Hash, path string, val []byte) error {
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

func (s *ShadowNodeStorageRW) OpenStorage(addr common.Hash) ShadowNodeStorage {
	return NewShadowNodeStorage4Trie(addr, s)
}

// Commit if you commit to an unknown parent, like deeper than 128 layers, will get error
func (s *ShadowNodeStorageRW) Commit(number *big.Int, blockRoot common.Hash) error {
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
