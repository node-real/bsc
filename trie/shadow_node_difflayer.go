package trie

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/RoaringBitmap/roaring/roaring64"
	"github.com/ethereum/go-ethereum/common/math"
	lru "github.com/hashicorp/golang-lru"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	// MaxShadowNodeDiffDepth default is 128 layers
	MaxShadowNodeDiffDepth           = 128
	journalVersion            uint64 = 1
	defaultDiskLayerCacheSize        = 100000
)

// shadowNodeSnapshot record diff layer and disk layer of shadow nodes, support mini reorg
type shadowNodeSnapshot interface {
	// Root block state root
	Root() common.Hash

	// ShadowNode query shadow node from db, got RLP format
	ShadowNode(addrHash common.Hash, path string) ([]byte, error)

	// Parent parent snap
	Parent() shadowNodeSnapshot

	// Update create a new diff layer from here
	Update(blockNumber *big.Int, blockRoot common.Hash, nodeSet map[common.Hash]map[string][]byte) (shadowNodeSnapshot, error)

	// Journal commit self as a journal to buffer
	Journal(buffer *bytes.Buffer) (common.Hash, error)
}

// ShadowNodeSnapTree maintain all diff layers support reorg, will flush to db when MaxShadowNodeDiffDepth reach
// every layer response to a block state change set, there no flatten layers operation.
type ShadowNodeSnapTree struct {
	diskdb ethdb.KeyValueStore

	// diffLayers + diskLayer, disk layer, always not nil
	layers   map[common.Hash]shadowNodeSnapshot
	children map[common.Hash][]common.Hash

	lock sync.RWMutex
}

func NewShadowNodeSnapTree(diskdb ethdb.KeyValueStore) (*ShadowNodeSnapTree, error) {
	diskLayer, err := loadDiskLayer(diskdb)
	if err != nil {
		return nil, err
	}
	layers, children, err := loadDiffLayers(diskdb, diskLayer)
	if err != nil {
		return nil, err
	}

	layers[diskLayer.blockRoot] = diskLayer
	// check if continuously after disk layer
	if len(layers) > 1 && len(children[diskLayer.blockRoot]) == 0 {
		return nil, errors.New("cannot found any diff layers link to disk layer")
	}
	return &ShadowNodeSnapTree{
		diskdb:   diskdb,
		layers:   layers,
		children: children,
	}, nil
}

// Cap keep tree depth not greater MaxShadowNodeDiffDepth, all forks parent to disk layer will delete
func (s *ShadowNodeSnapTree) Cap(blockRoot common.Hash) error {
	snap := s.Snapshot(blockRoot)
	if snap == nil {
		return errors.New("snapshot missing")
	}
	nextDiff, ok := snap.(*shadowNodeDiffLayer)
	if !ok {
		return nil
	}
	for i := 0; i < MaxShadowNodeDiffDepth-1; i++ {
		nextDiff, ok = nextDiff.Parent().(*shadowNodeDiffLayer)
		// if depth less MaxShadowNodeDiffDepth, just return
		if !ok {
			return nil
		}
	}

	flatten := make([]shadowNodeSnapshot, 0)
	parent := nextDiff.Parent()
	for parent != nil {
		flatten = append(flatten, parent)
		parent = parent.Parent()
	}
	if len(flatten) <= 1 {
		return nil
	}

	last, ok := flatten[len(flatten)-1].(*shadowNodeDiskLayer)
	if !ok {
		return errors.New("the diff layers not link to disk layer")
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	newDiskLayer, err := s.flattenDiffs2Disk(flatten[:len(flatten)-1], last)
	if err != nil {
		return err
	}

	// clear forks, but keep latest disk forks
	for i := len(flatten) - 1; i > 0; i-- {
		var childRoot common.Hash
		if i > 0 {
			childRoot = flatten[i-1].Root()
		} else {
			childRoot = nextDiff.Root()
		}
		root := flatten[i].Root()
		s.removeSubLayers(s.children[root], &childRoot)
		delete(s.layers, root)
		delete(s.children, root)
	}

	// reset newDiskLayer and children's parent
	s.layers[newDiskLayer.Root()] = newDiskLayer
	for _, child := range s.children[newDiskLayer.Root()] {
		if diff, exist := s.layers[child].(*shadowNodeDiffLayer); exist {
			diff.setParent(newDiskLayer)
		}
	}
	return nil
}

func (s *ShadowNodeSnapTree) Update(parentRoot common.Hash, blockNumber *big.Int, blockRoot common.Hash, nodeSet map[common.Hash]map[string][]byte) error {
	// if there are no changes, just skip
	if blockRoot == parentRoot {
		return nil
	}

	// Generate a new snapshot on top of the parent
	parent := s.Snapshot(parentRoot)
	if parent == nil {
		// just point to fake disk layers
		parent = s.Snapshot(emptyRoot)
		if parent == nil {
			return errors.New("cannot find any suitable parent")
		}
		parentRoot = parent.Root()
	}
	snap, err := parent.Update(blockNumber, blockRoot, nodeSet)
	if err != nil {
		return err
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	s.layers[blockRoot] = snap
	s.children[parentRoot] = append(s.children[parentRoot], blockRoot)
	return nil
}

func (s *ShadowNodeSnapTree) Snapshot(blockRoot common.Hash) shadowNodeSnapshot {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.layers[blockRoot]
}

func (s *ShadowNodeSnapTree) DB() ethdb.KeyValueStore {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.diskdb
}

func (s *ShadowNodeSnapTree) Journal() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Firstly write out the metadata of journal
	journal := new(bytes.Buffer)
	if err := rlp.Encode(journal, journalVersion); err != nil {
		return err
	}
	for _, snap := range s.layers {
		if _, err := snap.Journal(journal); err != nil {
			return err
		}
	}
	rawdb.WriteShadowNodeSnapshotJournal(s.diskdb, journal.Bytes())
	return nil
}

func (s *ShadowNodeSnapTree) removeSubLayers(layers []common.Hash, skip *common.Hash) {
	for _, layer := range layers {
		if skip != nil && layer == *skip {
			continue
		}
		s.removeSubLayers(s.children[layer], nil)
		delete(s.layers, layer)
		delete(s.children, layer)
	}
}

// flattenDiffs2Disk delete all flatten and push them to db
func (s *ShadowNodeSnapTree) flattenDiffs2Disk(flatten []shadowNodeSnapshot, diskLayer *shadowNodeDiskLayer) (*shadowNodeDiskLayer, error) {
	var err error
	for i := len(flatten) - 1; i >= 0; i-- {
		diskLayer, err = diskLayer.PushDiff(flatten[i].(*shadowNodeDiffLayer))
		if err != nil {
			return nil, err
		}
	}

	return diskLayer, nil
}

// loadDiskLayer load from db, could be nil when none in db
func loadDiskLayer(db ethdb.KeyValueStore) (*shadowNodeDiskLayer, error) {
	val := rawdb.ReadShadowNodePlainStateMeta(db)
	// if there is no disk layer, will construct a fake disk layer
	if len(val) == 0 {
		diskLayer, err := newShadowNodeDiskLayer(db, common.Big0, emptyRoot)
		if err != nil {
			return nil, err
		}
		return diskLayer, nil
	}
	var meta shadowNodePlainMeta
	if err := rlp.DecodeBytes(val, &meta); err != nil {
		return nil, err
	}

	layer, err := newShadowNodeDiskLayer(db, meta.BlockNumber, meta.BlockRoot)
	if err != nil {
		return nil, err
	}
	return layer, nil
}

func loadDiffLayers(db ethdb.KeyValueStore, diskLayer *shadowNodeDiskLayer) (map[common.Hash]shadowNodeSnapshot, map[common.Hash][]common.Hash, error) {
	layers := make(map[common.Hash]shadowNodeSnapshot)
	children := make(map[common.Hash][]common.Hash)

	journal := rawdb.ReadShadowNodeSnapshotJournal(db)
	if len(journal) == 0 {
		return layers, children, nil
	}
	r := rlp.NewStream(bytes.NewReader(journal), 0)
	// Firstly, resolve the first element as the journal version
	version, err := r.Uint64()
	if err != nil {
		return nil, nil, errors.New("failed to resolve journal version")
	}
	if version != journalVersion {
		return nil, nil, errors.New("wrong journal version")
	}

	parents := make(map[common.Hash]common.Hash)
	for {
		var (
			parent common.Hash
			number big.Int
			root   common.Hash
			js     []journalShadowNode
		)
		// Read the next diff journal entry
		if err := r.Decode(&number); err != nil {
			// The first read may fail with EOF, marking the end of the journal
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, nil, fmt.Errorf("load diff number: %v", err)
		}
		if err := r.Decode(&parent); err != nil {
			return nil, nil, fmt.Errorf("load diff parent: %v", err)
		}
		// Read the next diff journal entry
		if err := r.Decode(&root); err != nil {
			return nil, nil, fmt.Errorf("load diff root: %v", err)
		}
		if err := r.Decode(&js); err != nil {
			return nil, nil, fmt.Errorf("load diff storage: %v", err)
		}

		nodeSet := make(map[common.Hash]map[string][]byte)
		for _, entry := range js {
			nodes := make(map[string][]byte)
			for i, key := range entry.Keys {
				if len(entry.Vals[i]) > 0 { // RLP loses nil-ness, but `[]byte{}` is not a valid item, so reinterpret that
					nodes[key] = entry.Vals[i]
				} else {
					nodes[key] = nil
				}
			}
			nodeSet[entry.Hash] = nodes
		}

		parents[root] = parent
		layers[root] = newShadowNodeDiffLayer(&number, root, nil, nodeSet)
	}

	for t, s := range layers {
		parent := parents[t]
		children[parent] = append(children[parent], t)
		if p, ok := layers[parent]; ok {
			s.(*shadowNodeDiffLayer).parent = p
		} else if diskLayer != nil && parent == diskLayer.Root() {
			s.(*shadowNodeDiffLayer).parent = diskLayer
		} else {
			return nil, nil, errors.New("cannot find it's parent")
		}
	}
	return layers, children, nil
}

type shadowNodeDiffLayer struct {
	blockNumber *big.Int
	blockRoot   common.Hash
	parent      shadowNodeSnapshot
	nodeSet     map[common.Hash]map[string][]byte

	// TODO(0xbundler): add destruct handle later?
	lock sync.RWMutex
}

func newShadowNodeDiffLayer(blockNumber *big.Int, blockRoot common.Hash, parent shadowNodeSnapshot, nodeSet map[common.Hash]map[string][]byte) *shadowNodeDiffLayer {
	return &shadowNodeDiffLayer{
		blockNumber: blockNumber,
		blockRoot:   blockRoot,
		parent:      parent,
		nodeSet:     nodeSet,
	}
}

func (s *shadowNodeDiffLayer) Root() common.Hash {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.blockRoot
}

func (s *shadowNodeDiffLayer) ShadowNode(addrHash common.Hash, path string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	cm, exist := s.nodeSet[addrHash]
	if exist {
		if ret, ok := cm[path]; ok {
			return ret, nil
		}
	}

	return s.parent.ShadowNode(addrHash, path)
}

func (s *shadowNodeDiffLayer) Parent() shadowNodeSnapshot {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.parent
}

// Update append new diff layer onto current, nodeChgRecord when val is []byte{}, it delete the kv
func (s *shadowNodeDiffLayer) Update(blockNumber *big.Int, blockRoot common.Hash, nodeSet map[common.Hash]map[string][]byte) (shadowNodeSnapshot, error) {
	s.lock.RLock()
	if s.blockNumber.Cmp(blockNumber) >= 0 {
		return nil, errors.New("update a unordered diff layer")
	}
	s.lock.RUnlock()
	return newShadowNodeDiffLayer(blockNumber, blockRoot, s, nodeSet), nil
}

func (s *shadowNodeDiffLayer) Journal(buffer *bytes.Buffer) (common.Hash, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if err := rlp.Encode(buffer, s.blockNumber); err != nil {
		return common.Hash{}, err
	}

	if s.parent != nil {
		if err := rlp.Encode(buffer, s.parent.Root()); err != nil {
			return common.Hash{}, err
		}
	} else {
		if err := rlp.Encode(buffer, emptyRoot); err != nil {
			return common.Hash{}, err
		}
	}

	if err := rlp.Encode(buffer, s.blockRoot); err != nil {
		return common.Hash{}, err
	}
	storage := make([]journalShadowNode, 0, len(s.nodeSet))
	for hash, nodes := range s.nodeSet {
		keys := make([]string, 0, len(nodes))
		vals := make([][]byte, 0, len(nodes))
		for key, val := range nodes {
			keys = append(keys, key)
			vals = append(vals, val)
		}
		storage = append(storage, journalShadowNode{Hash: hash, Keys: keys, Vals: vals})
	}
	if err := rlp.Encode(buffer, storage); err != nil {
		return common.Hash{}, err
	}
	return s.blockRoot, nil
}

func (s *shadowNodeDiffLayer) setParent(parent shadowNodeSnapshot) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.parent = parent
}

func (s *shadowNodeDiffLayer) getNodeSet() map[common.Hash]map[string][]byte {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.nodeSet
}

type journalShadowNode struct {
	Hash common.Hash
	Keys []string
	Vals [][]byte
}

type shadowNodePlainMeta struct {
	BlockNumber *big.Int
	BlockRoot   common.Hash
}

type shadowNodeDiskLayer struct {
	// TODO(0xbundler): add history & changeSet later
	diskdb      ethdb.KeyValueStore
	blockNumber *big.Int
	blockRoot   common.Hash
	cache       *lru.Cache

	lock sync.RWMutex
}

func newShadowNodeDiskLayer(diskdb ethdb.KeyValueStore, blockNumber *big.Int, blockRoot common.Hash) (*shadowNodeDiskLayer, error) {
	cache, err := lru.New(defaultDiskLayerCacheSize)
	if err != nil {
		return nil, err
	}
	return &shadowNodeDiskLayer{
		diskdb:      diskdb,
		blockNumber: blockNumber,
		blockRoot:   blockRoot,
		cache:       cache,
	}, nil
}

func (s *shadowNodeDiskLayer) Root() common.Hash {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.blockRoot
}

func (s *shadowNodeDiskLayer) ShadowNode(addr common.Hash, path string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	cacheKey := shadowNodeCacheKey(addr, path)
	cached, exist := s.cache.Get(cacheKey)
	if exist {
		return cached.([]byte), nil
	}

	val, err := FindHistory(s.diskdb, s.blockNumber.Uint64()+1, addr, path)
	if err != nil {
		return nil, err
	}

	s.cache.Add(cacheKey, val)
	return val, err
}

func (s *shadowNodeDiskLayer) Parent() shadowNodeSnapshot {
	return nil
}

func (s *shadowNodeDiskLayer) Update(blockNumber *big.Int, blockRoot common.Hash, nodeSet map[common.Hash]map[string][]byte) (shadowNodeSnapshot, error) {
	s.lock.RLock()
	if s.blockNumber.Cmp(blockNumber) >= 0 {
		return nil, errors.New("update a unordered diff layer")
	}
	s.lock.RUnlock()
	return newShadowNodeDiffLayer(blockNumber, blockRoot, s, nodeSet), nil
}

func (s *shadowNodeDiskLayer) Journal(buffer *bytes.Buffer) (common.Hash, error) {
	return common.Hash{}, nil
}

func (s *shadowNodeDiskLayer) PushDiff(diff *shadowNodeDiffLayer) (*shadowNodeDiskLayer, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	number := diff.blockNumber
	if s.blockNumber.Cmp(number) >= 0 {
		return nil, errors.New("push a lower block to disk")
	}
	batch := s.diskdb.NewBatch()
	nodeSet := diff.getNodeSet()
	for addr, subSet := range nodeSet {
		changeSet := make([]nodeChgRecord, 0, len(subSet))
		for path, val := range subSet {
			if err := refreshShadowNodeHistory(s.diskdb, batch, addr, path, number.Uint64()); err != nil {
				return nil, err
			}
			prev := rawdb.ReadShadowNodePlainState(s.diskdb, addr, path)
			// refresh plain state
			if len(val) == 0 {
				if err := rawdb.DeleteShadowNodePlainState(batch, addr, path); err != nil {
					return nil, err
				}
			} else {
				if err := rawdb.WriteShadowNodePlainState(batch, addr, path, val); err != nil {
					return nil, err
				}
			}

			changeSet = append(changeSet, nodeChgRecord{
				Path: path,
				Prev: prev,
			})
		}
		enc, err := rlp.EncodeToBytes(changeSet)
		if err != nil {
			return nil, err
		}
		if err = rawdb.WriteShadowNodeChangeSet(batch, addr, number.Uint64(), enc); err != nil {
			return nil, err
		}
	}

	// update meta
	meta := shadowNodePlainMeta{
		BlockNumber: number,
		BlockRoot:   diff.blockRoot,
	}
	enc, err := rlp.EncodeToBytes(meta)
	if err != nil {
		return nil, err
	}
	if err = rawdb.WriteShadowNodePlainStateMeta(batch, enc); err != nil {
		return nil, err
	}

	if err = batch.Write(); err != nil {
		return nil, err
	}
	diskLayer := &shadowNodeDiskLayer{
		diskdb:      s.diskdb,
		blockNumber: number,
		blockRoot:   diff.blockRoot,
		cache:       s.cache,
	}

	// reuse cache
	for addr, nodes := range diff.nodeSet {
		for path, val := range nodes {
			diskLayer.cache.Add(shadowNodeCacheKey(addr, path), val)
		}
	}
	return diskLayer, nil
}

func shadowNodeCacheKey(addr common.Hash, path string) string {
	key := make([]byte, len(addr)+len(path))
	copy(key[:], addr.Bytes())
	copy(key[len(addr):], path)
	return string(key)
}

func refreshShadowNodeHistory(db ethdb.KeyValueReader, batch ethdb.Batch, addr common.Hash, path string, number uint64) error {
	enc := rawdb.ReadShadowNodeHistory(db, addr, path, math.MaxUint64)
	index := roaring64.New()
	if len(enc) > 0 {
		if _, err := index.ReadFrom(bytes.NewReader(enc)); err != nil {
			return err
		}
	}
	index.Add(number)
	enc, err := index.ToBytes()
	if err != nil {
		return err
	}
	if err = rawdb.WriteShadowNodeHistory(batch, addr, path, math.MaxUint64, enc); err != nil {
		return err
	}
	return nil
}
