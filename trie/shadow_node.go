package trie

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/ethereum/go-ethereum/ethdb"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const (
	ShadowTreeRootNodePath = "s"
)

type rootNode struct {
	Epoch          types.StateEpoch
	TrieRoot       common.Hash
	ShadowTreeRoot common.Hash
	cachedHash     common.Hash `rlp:"-" json:"-"`
	cachedEnc      []byte      `rlp:"-" json:"-"`
}

func newEpoch0RootNode(trieRoot common.Hash) *rootNode {
	return newRootNode(types.StateEpoch0, trieRoot, emptyRoot)
}

func newRootNode(epoch types.StateEpoch, trieRoot, shadowTreeRoot common.Hash) *rootNode {
	n := &rootNode{
		Epoch:          epoch,
		TrieRoot:       trieRoot,
		ShadowTreeRoot: shadowTreeRoot,
	}
	n.resolveCache()
	return n
}

func (n *rootNode) copy() *rootNode { copy := *n; return &copy }

func (n *rootNode) encode(w rlp.EncoderBuffer) {
	rlp.Encode(w, n)
}

func (n *rootNode) cache() (hashNode, bool) { return n.cachedHash[:], true }

func (n *rootNode) setEpoch(epoch types.StateEpoch) { n.Epoch = epoch }
func (n *rootNode) getEpoch() types.StateEpoch      { return n.Epoch }

func (n *rootNode) String() string { return n.fstring("") }

func (n *rootNode) fstring(ind string) string {
	return fmt.Sprintf("rootNode{epoch:%d, trieRoot:%s, shadowTreeRoot:%s}", n.Epoch, n.TrieRoot, n.ShadowTreeRoot)
}

func (n *rootNode) nodeType() int {
	return rootNodeType
}

func (n *rootNode) resolveCache() {
	buf := rlp.NewEncoderBuffer(nil)
	n.encode(buf)
	n.cachedEnc = buf.ToBytes()

	// cache hash
	h := newHasher(false)
	h.sha.Reset()
	h.sha.Write(n.cachedEnc)
	h.sha.Read(n.cachedHash[:])
	returnHasherToPool(h)
}

func decodeRootNode(enc []byte) (*rootNode, error) {
	n := &rootNode{}
	if err := rlp.DecodeBytes(enc, n); err != nil {
		return nil, err
	}
	n.resolveCache()
	return n, nil
}

type shadowExtensionNode struct {
	ShadowHash *common.Hash
}

func NewShadowExtensionNode(hash *common.Hash) shadowExtensionNode {
	return shadowExtensionNode{
		ShadowHash: hash,
	}
}

func (n *shadowExtensionNode) encode(w rlp.EncoderBuffer) {
	offset := w.List()
	if n.ShadowHash == nil {
		w.Write(rlp.EmptyString)
	} else {
		w.WriteBytes(n.ShadowHash[:])
	}
	w.ListEnd(offset)
}

func decodeShadowExtensionNode(enc []byte) (*shadowExtensionNode, error) {
	var n shadowExtensionNode
	elems, _, err := rlp.SplitList(enc)
	if err != nil {
		return nil, err
	}

	sh, _, err := rlp.SplitString(elems)
	if err != nil {
		return nil, err
	}

	if len(sh) == 0 {
		n.ShadowHash = nil
	} else {
		hash := common.BytesToHash(sh)
		n.ShadowHash = &hash
	}
	return &n, nil
}

type shadowBranchNode struct {
	ShadowHash *common.Hash
	EpochMap   [16]types.StateEpoch
}

func NewShadowBranchNode(hash *common.Hash, epochMap [16]types.StateEpoch) shadowBranchNode {
	return shadowBranchNode{hash, epochMap}
}
func (n *shadowBranchNode) encode(w rlp.EncoderBuffer) {
	offset := w.List()
	if n.ShadowHash == nil {
		w.Write(rlp.EmptyString)
	} else {
		w.WriteBytes(n.ShadowHash[:])
	}
	epochsList := w.List()
	for _, e := range n.EpochMap {
		w.WriteUint64(uint64(e))
	}
	w.ListEnd(epochsList)
	w.ListEnd(offset)
}

func decodeShadowBranchNode(enc []byte) (*shadowBranchNode, error) {
	var n shadowBranchNode
	elems, _, err := rlp.SplitList(enc)
	if err != nil {
		return nil, err
	}

	sh, rest, err := rlp.SplitString(elems)
	if err != nil {
		return nil, err
	}

	if len(sh) == 0 {
		n.ShadowHash = nil
	} else {
		hash := common.BytesToHash(sh)
		n.ShadowHash = &hash
	}

	if err = rlp.DecodeBytes(rest, &n.EpochMap); err != nil {
		return nil, err
	}

	return &n, nil
}

type ShadowNodeStorage interface {
	// Get key is the shadow node prefix path
	Get(path string) ([]byte, error)
	Put(path string, val []byte) error
	Delete(path string) error
}

type ShadowNodeDatabase interface {
	Get(addr common.Hash, path string) ([]byte, error)
	Delete(addr common.Hash, path string) error
	Put(addr common.Hash, path string, val []byte) error
	OpenStorage(addr common.Hash) ShadowNodeStorage
	Commit(number *big.Int, blockRoot common.Hash) error
}

type shadowNodeStorage4Trie struct {
	addr common.Hash
	db   ShadowNodeDatabase
}

func NewShadowNodeStorage4Trie(addr common.Hash, db ShadowNodeDatabase) ShadowNodeStorage {
	return &shadowNodeStorage4Trie{
		addr: addr,
		db:   db,
	}
}

func (s *shadowNodeStorage4Trie) Get(path string) ([]byte, error) {
	return s.db.Get(s.addr, path)
}

func (s *shadowNodeStorage4Trie) Put(path string, val []byte) error {
	return s.db.Put(s.addr, path, val)
}

func (s *shadowNodeStorage4Trie) Delete(path string) error {
	return s.db.Delete(s.addr, path)
}

// ShadowNodeStorageRO shadow node only could modify the latest diff layers,
// if you want to modify older state, please unwind to thr older history
type ShadowNodeStorageRO struct {
	diskdb ethdb.KeyValueStore
	number *big.Int
}

func (s *ShadowNodeStorageRO) Get(addr common.Hash, path string) ([]byte, error) {
	return FindHistory(s.diskdb, s.number.Uint64()+1, addr, path)
}

func (s *ShadowNodeStorageRO) Delete(addr common.Hash, path string) error {
	return errors.New("ShadowNodeStorageRO unsupported")
}

func (s *ShadowNodeStorageRO) Put(addr common.Hash, path string, val []byte) error {
	return errors.New("ShadowNodeStorageRO unsupported")
}

func (s *ShadowNodeStorageRO) OpenStorage(addr common.Hash) ShadowNodeStorage {
	return NewShadowNodeStorage4Trie(addr, s)
}

func (s *ShadowNodeStorageRO) Commit(number *big.Int, blockRoot common.Hash) error {
	return errors.New("ShadowNodeStorageRO unsupported")
}

type ShadowNodeStorageRW struct {
	snap    shadowNodeSnapshot
	tree    *ShadowNodeSnapTree
	dirties map[common.Hash]map[string][]byte

	stale bool
	lock  sync.RWMutex
}

// NewShadowNodeDatabase first find snap by blockRoot, if got nil, try using number to instance a read only storage
func NewShadowNodeDatabase(tree *ShadowNodeSnapTree, number *big.Int, blockRoot common.Hash) (ShadowNodeDatabase, error) {
	snap := tree.Snapshot(blockRoot)
	if snap == nil {
		// try using default snap
		if snap = tree.Snapshot(emptyRoot); snap == nil {
			// open read only history
			log.Debug("NewShadowNodeDatabase use RO database", "number", number, "root", blockRoot)
			return &ShadowNodeStorageRO{
				diskdb: tree.DB(),
				number: number,
			}, nil
		}
		log.Debug("NewShadowNodeDatabase use default database", "number", number, "root", blockRoot)
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
