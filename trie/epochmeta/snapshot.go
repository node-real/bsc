package epochmeta

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"io"
	"math/big"
	"sync"
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

type Config struct {
	capLimit int // it indicates how depth diff layer to keep
}

var Defaults = &Config{
	capLimit: MaxEpochMetaDiffDepth,
}

// SnapshotTree maintain all diff layers support reorg, will flush to db when MaxEpochMetaDiffDepth reach
// every layer response to a block state change set, there no flatten layers operation.
type SnapshotTree struct {
	diskdb ethdb.KeyValueStore

	// diffLayers + diskLayer, disk layer, always not nil
	layers   map[common.Hash]snapshot
	children map[common.Hash][]common.Hash
	cfg      *Config

	lock sync.RWMutex
}

func NewEpochMetaSnapTree(diskdb ethdb.KeyValueStore, cfg *Config) (*SnapshotTree, error) {
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

	if cfg == nil {
		cfg = Defaults
	}
	return &SnapshotTree{
		diskdb:   diskdb,
		layers:   layers,
		children: children,
		cfg:      cfg,
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
	for i := 0; i < s.cfg.capLimit-1; i++ {
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
			diff.resetParent(newDiskLayer)
		}
	}
	log.Info("SnapshotTree cap", "layers", len(s.layers), "children", len(s.children), "flatten", len(flatten))
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

type diffTmp struct {
	parent  common.Hash
	number  big.Int
	root    common.Hash
	nodeSet map[common.Hash]map[string][]byte
}

func loadDiffLayers(db ethdb.KeyValueStore, dl *diskLayer) (map[common.Hash]snapshot, map[common.Hash][]common.Hash, error) {
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

	diffTmps := make(map[common.Hash]diffTmp)
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

		diffTmps[root] = diffTmp{
			parent:  parent,
			number:  number,
			root:    root,
			nodeSet: nodeSet,
		}
		children[parent] = append(children[parent], root)

		parents[root] = parent
		layers[root] = newEpochMetaDiffLayer(&number, root, dl, nodeSet)
	}

	// rebuild diff layers from disk layer
	rebuildFromParent(dl, children, layers, diffTmps)
	return layers, children, nil
}

func rebuildFromParent(p snapshot, children map[common.Hash][]common.Hash, layers map[common.Hash]snapshot, diffTmps map[common.Hash]diffTmp) {
	subs := children[p.Root()]
	for _, cur := range subs {
		df := diffTmps[cur]
		layers[cur] = newEpochMetaDiffLayer(&df.number, df.root, p, df.nodeSet)
		rebuildFromParent(layers[cur], children, layers, diffTmps)
	}
}
