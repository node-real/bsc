package epochmeta

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
	"io"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/log"

	lru "github.com/hashicorp/golang-lru"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	// MaxEpochMetaDiffDepth default is 128 layers
	MaxEpochMetaDiffDepth            = 128
	journalVersion            uint64 = 1
	defaultDiskLayerCacheSize        = 100000
)

// snapshot record diff layer and disk layer of shadow nodes, support mini reorg
type snapshot interface {
	// Root block state root
	Root() common.Hash

	// EpochMeta query shadow node from db, got RLP format
	EpochMeta(addrHash common.Hash, path string) ([]byte, error)

	// Parent parent snap
	Parent() snapshot

	// Update create a new diff layer from here
	Update(blockNumber *big.Int, blockRoot common.Hash, nodeSet map[common.Hash]map[string][]byte) (snapshot, error)

	// Journal commit self as a journal to buffer
	Journal(buffer *bytes.Buffer) (common.Hash, error)
}

// SnapshotTree maintain all diff layers support reorg, will flush to db when MaxEpochMetaDiffDepth reach
// every layer response to a block state change set, there no flatten layers operation.
type SnapshotTree struct {
	diskdb ethdb.KeyValueStore

	// diffLayers + diskLayer, disk layer, always not nil
	layers   map[common.Hash]snapshot
	children map[common.Hash][]common.Hash

	lock sync.RWMutex
}

func NewEpochMetaSnapTree(diskdb ethdb.KeyValueStore) (*SnapshotTree, error) {
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
	return &SnapshotTree{
		diskdb:   diskdb,
		layers:   layers,
		children: children,
	}, nil
}

// Cap keep tree depth not greater MaxEpochMetaDiffDepth, all forks parent to disk layer will delete
func (s *SnapshotTree) Cap(blockRoot common.Hash) error {
	snap := s.Snapshot(blockRoot)
	if snap == nil {
		return fmt.Errorf("epoch meta snapshot missing: [%#x]", blockRoot)
	}
	nextDiff, ok := snap.(*diffLayer)
	if !ok {
		return nil
	}
	for i := 0; i < MaxEpochMetaDiffDepth-1; i++ {
		nextDiff, ok = nextDiff.Parent().(*diffLayer)
		// if depth less MaxEpochMetaDiffDepth, just return
		if !ok {
			return nil
		}
	}

	flatten := make([]snapshot, 0)
	parent := nextDiff.Parent()
	for parent != nil {
		flatten = append(flatten, parent)
		parent = parent.Parent()
	}
	if len(flatten) <= 1 {
		return nil
	}

	last, ok := flatten[len(flatten)-1].(*diskLayer)
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
		if diff, exist := s.layers[child].(*diffLayer); exist {
			diff.setParent(newDiskLayer)
		}
	}
	return nil
}

func (s *SnapshotTree) Update(parentRoot common.Hash, blockNumber *big.Int, blockRoot common.Hash, nodeSet map[common.Hash]map[string][]byte) error {
	// if there are no changes, just skip
	if blockRoot == parentRoot {
		return nil
	}

	// Generate a new snapshot on top of the parent
	parent := s.Snapshot(parentRoot)
	if parent == nil {
		// just point to fake disk layers
		parent = s.Snapshot(types.EmptyRootHash)
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

func (s *SnapshotTree) Snapshot(blockRoot common.Hash) snapshot {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.layers[blockRoot]
}

func (s *SnapshotTree) DB() ethdb.KeyValueStore {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.diskdb
}

func (s *SnapshotTree) Journal() error {
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
	rawdb.WriteEpochMetaSnapshotJournal(s.diskdb, journal.Bytes())
	return nil
}

func (s *SnapshotTree) removeSubLayers(layers []common.Hash, skip *common.Hash) {
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
func (s *SnapshotTree) flattenDiffs2Disk(flatten []snapshot, diskLayer *diskLayer) (*diskLayer, error) {
	var err error
	for i := len(flatten) - 1; i >= 0; i-- {
		diskLayer, err = diskLayer.PushDiff(flatten[i].(*diffLayer))
		if err != nil {
			return nil, err
		}
	}

	return diskLayer, nil
}

// loadDiskLayer load from db, could be nil when none in db
func loadDiskLayer(db ethdb.KeyValueStore) (*diskLayer, error) {
	val := rawdb.ReadEpochMetaPlainStateMeta(db)
	// if there is no disk layer, will construct a fake disk layer
	if len(val) == 0 {
		diskLayer, err := newEpochMetaDiskLayer(db, common.Big0, types.EmptyRootHash)
		if err != nil {
			return nil, err
		}
		return diskLayer, nil
	}
	var meta epochMetaPlainMeta
	if err := rlp.DecodeBytes(val, &meta); err != nil {
		return nil, err
	}

	layer, err := newEpochMetaDiskLayer(db, meta.BlockNumber, meta.BlockRoot)
	if err != nil {
		return nil, err
	}
	return layer, nil
}

func loadDiffLayers(db ethdb.KeyValueStore, diskLayer *diskLayer) (map[common.Hash]snapshot, map[common.Hash][]common.Hash, error) {
	layers := make(map[common.Hash]snapshot)
	children := make(map[common.Hash][]common.Hash)

	journal := rawdb.ReadEpochMetaSnapshotJournal(db)
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
			js     []journalEpochMeta
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
		layers[root] = newEpochMetaDiffLayer(&number, root, nil, nodeSet)
	}

	for t, s := range layers {
		parent := parents[t]
		children[parent] = append(children[parent], t)
		if p, ok := layers[parent]; ok {
			s.(*diffLayer).parent = p
		} else if diskLayer != nil && parent == diskLayer.Root() {
			s.(*diffLayer).parent = diskLayer
		} else {
			return nil, nil, errors.New("cannot find it's parent")
		}
	}
	return layers, children, nil
}

// TODO(0xbundler): add bloom filter?
type diffLayer struct {
	blockNumber *big.Int
	blockRoot   common.Hash
	parent      snapshot
	nodeSet     map[common.Hash]map[string][]byte
	lock        sync.RWMutex
}

func newEpochMetaDiffLayer(blockNumber *big.Int, blockRoot common.Hash, parent snapshot, nodeSet map[common.Hash]map[string][]byte) *diffLayer {
	return &diffLayer{
		blockNumber: blockNumber,
		blockRoot:   blockRoot,
		parent:      parent,
		nodeSet:     nodeSet,
	}
}

func (s *diffLayer) Root() common.Hash {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.blockRoot
}

func (s *diffLayer) EpochMeta(addrHash common.Hash, path string) ([]byte, error) {
	// TODO(0xbundler): remove lock?
	s.lock.RLock()
	defer s.lock.RUnlock()
	// TODO(0xbundler): difflayer cache hit rate.
	cm, exist := s.nodeSet[addrHash]
	if exist {
		if ret, ok := cm[path]; ok {
			return ret, nil
		}
	}

	return s.parent.EpochMeta(addrHash, path)
}

func (s *diffLayer) Parent() snapshot {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.parent
}

// Update append new diff layer onto current, nodeChgRecord when val is []byte{}, it delete the kv
func (s *diffLayer) Update(blockNumber *big.Int, blockRoot common.Hash, nodeSet map[common.Hash]map[string][]byte) (snapshot, error) {
	s.lock.RLock()
	if s.blockNumber.Int64() != 0 && s.blockNumber.Cmp(blockNumber) >= 0 {
		return nil, errors.New("update a unordered diff layer in diff layer")
	}
	s.lock.RUnlock()
	return newEpochMetaDiffLayer(blockNumber, blockRoot, s, nodeSet), nil
}

func (s *diffLayer) Journal(buffer *bytes.Buffer) (common.Hash, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if err := rlp.Encode(buffer, s.blockNumber); err != nil {
		return common.Hash{}, err
	}

	if s.parent == nil {
		return common.Hash{}, errors.New("found nil parent in Journal")
	}

	if err := rlp.Encode(buffer, s.parent.Root()); err != nil {
		return common.Hash{}, err
	}

	if err := rlp.Encode(buffer, s.blockRoot); err != nil {
		return common.Hash{}, err
	}
	storage := make([]journalEpochMeta, 0, len(s.nodeSet))
	for hash, nodes := range s.nodeSet {
		keys := make([]string, 0, len(nodes))
		vals := make([][]byte, 0, len(nodes))
		for key, val := range nodes {
			keys = append(keys, key)
			vals = append(vals, val)
		}
		storage = append(storage, journalEpochMeta{Hash: hash, Keys: keys, Vals: vals})
	}
	if err := rlp.Encode(buffer, storage); err != nil {
		return common.Hash{}, err
	}
	return s.blockRoot, nil
}

func (s *diffLayer) setParent(parent snapshot) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.parent = parent
}

func (s *diffLayer) getNodeSet() map[common.Hash]map[string][]byte {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.nodeSet
}

type journalEpochMeta struct {
	Hash common.Hash
	Keys []string
	Vals [][]byte
}

type epochMetaPlainMeta struct {
	BlockNumber *big.Int
	BlockRoot   common.Hash
}

type diskLayer struct {
	diskdb      ethdb.KeyValueStore
	blockNumber *big.Int
	blockRoot   common.Hash
	cache       *lru.Cache
	lock        sync.RWMutex
}

func newEpochMetaDiskLayer(diskdb ethdb.KeyValueStore, blockNumber *big.Int, blockRoot common.Hash) (*diskLayer, error) {
	cache, err := lru.New(defaultDiskLayerCacheSize)
	if err != nil {
		return nil, err
	}
	return &diskLayer{
		diskdb:      diskdb,
		blockNumber: blockNumber,
		blockRoot:   blockRoot,
		cache:       cache,
	}, nil
}

func (s *diskLayer) Root() common.Hash {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.blockRoot
}

func (s *diskLayer) EpochMeta(addr common.Hash, path string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	// TODO(0xbundler): disklayer cache hit rate.
	cacheKey := cacheKey(addr, path)
	cached, exist := s.cache.Get(cacheKey)
	if exist {
		return cached.([]byte), nil
	}

	val := rawdb.ReadEpochMetaPlainState(s.diskdb, addr, path)
	s.cache.Add(cacheKey, val)
	return val, nil
}

func (s *diskLayer) Parent() snapshot {
	return nil
}

func (s *diskLayer) Update(blockNumber *big.Int, blockRoot common.Hash, nodeSet map[common.Hash]map[string][]byte) (snapshot, error) {
	s.lock.RLock()
	if s.blockNumber.Int64() != 0 && s.blockNumber.Cmp(blockNumber) >= 0 {
		return nil, errors.New("update a unordered diff layer in disk layer")
	}
	s.lock.RUnlock()
	return newEpochMetaDiffLayer(blockNumber, blockRoot, s, nodeSet), nil
}

func (s *diskLayer) Journal(buffer *bytes.Buffer) (common.Hash, error) {
	return common.Hash{}, nil
}

func (s *diskLayer) PushDiff(diff *diffLayer) (*diskLayer, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	number := diff.blockNumber
	if s.blockNumber.Cmp(number) >= 0 {
		return nil, errors.New("push a lower block to disk")
	}
	batch := s.diskdb.NewBatch()
	nodeSet := diff.getNodeSet()
	if err := s.writeHistory(number, batch, diff.getNodeSet()); err != nil {
		return nil, err
	}

	// update meta
	meta := epochMetaPlainMeta{
		BlockNumber: number,
		BlockRoot:   diff.blockRoot,
	}
	enc, err := rlp.EncodeToBytes(meta)
	if err != nil {
		return nil, err
	}
	if err = rawdb.WriteEpochMetaPlainStateMeta(batch, enc); err != nil {
		return nil, err
	}

	if err = batch.Write(); err != nil {
		return nil, err
	}
	diskLayer := &diskLayer{
		diskdb:      s.diskdb,
		blockNumber: number,
		blockRoot:   diff.blockRoot,
		cache:       s.cache,
	}

	// reuse cache
	for addr, nodes := range nodeSet {
		for path, val := range nodes {
			diskLayer.cache.Add(cacheKey(addr, path), val)
		}
	}
	return diskLayer, nil
}

func (s *diskLayer) writeHistory(number *big.Int, batch ethdb.Batch, nodeSet map[common.Hash]map[string][]byte) error {
	for addr, subSet := range nodeSet {
		for path, val := range subSet {
			// refresh plain state
			if len(val) == 0 {
				if err := rawdb.DeleteEpochMetaPlainState(batch, addr, path); err != nil {
					return err
				}
			} else {
				if err := rawdb.WriteEpochMetaPlainState(batch, addr, path, val); err != nil {
					return err
				}
			}
		}
	}
	log.Debug("shadow node history pruned, only keep plainState", "number", number, "count", len(nodeSet))
	return nil
}

func cacheKey(addr common.Hash, path string) string {
	key := make([]byte, len(addr)+len(path))
	copy(key[:], addr.Bytes())
	copy(key[len(addr):], path)
	return string(key)
}
