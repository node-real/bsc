package trie

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
	"io"
	"math/big"
	"sync"
)

const (
	// MaxShadowNodeDiffDepth default is 128 layers
	MaxShadowNodeDiffDepth = 128
	journalVersion         = 1
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

// shadowNodeSnapTree maintain all diff layers support reorg, will flush to db when MaxShadowNodeDiffDepth reach
// every layer response to a block state change set, there no flatten layers operation.
type shadowNodeSnapTree struct {
	diskdb ethdb.KeyValueStore

	// diff layers
	layers   map[common.Hash]shadowNodeSnapshot
	children map[common.Hash][]common.Hash

	// disk layer
	// TODO(0xbundler): add disk layer for history & changeSet
	diskCache map[common.Hash]map[string][]byte

	lock sync.RWMutex
}

func newShadowNodeDiffTree(diskdb ethdb.KeyValueStore) (*shadowNodeSnapTree, error) {
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
	if len(children[diskLayer.blockRoot]) == 0 {
		return nil, errors.New("cannot found any diff layers link to disk layer")
	}
	return &shadowNodeSnapTree{
		diskdb:    diskdb,
		layers:    layers,
		children:  children,
		diskCache: make(map[common.Hash]map[string][]byte),
	}, nil
}

// Cap TODO(0xbundler): keep tree depth not greater MaxShadowNodeDiffDepth, all forks parent to disk layer will delete
// TODO(0xbundler): store disk layer meta(blockNumber, blockRoot) too
func (s *shadowNodeSnapTree) Cap(blockRoot common.Hash) error {
	return nil
}

func (s *shadowNodeSnapTree) Update(parentRoot common.Hash, blockNumber *big.Int, blockRoot common.Hash, nodeSet map[common.Hash]map[string][]byte) error {
	if blockRoot == parentRoot {
		return errors.New("snapshot cycle")
	}
	// Generate a new snapshot on top of the parent
	parent := s.Snapshot(parentRoot)
	if parent == nil {
		return fmt.Errorf("parent snapshot missing")
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

func (s *shadowNodeSnapTree) Snapshot(blockRoot common.Hash) shadowNodeSnapshot {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.layers[blockRoot]
}

func (s *shadowNodeSnapTree) Journal() error {
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

func loadDiskLayer(db ethdb.KeyValueStore) (*shadowNodeDiskLayer, error) {
	// TODO(0xbundler): load disk layer meta(blockNumber, blockRoot)
	return newShadowNodeDiskLayer(db, common.Big0, common.Hash{})
}

func loadDiffLayers(db ethdb.KeyValueStore, diskLayer *shadowNodeDiskLayer) (map[common.Hash]shadowNodeSnapshot, map[common.Hash][]common.Hash, error) {
	journal := rawdb.ReadShadowNodeSnapshotJournal(db)
	if len(journal) == 0 {
		return nil, nil, errors.New("journal is empty")
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

	layers := make(map[common.Hash]shadowNodeSnapshot)
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
			return nil, nil, fmt.Errorf("load diff parent: %v", err)
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

	children := make(map[common.Hash][]common.Hash)
	for t, s := range layers {
		parent := parents[t]
		children[parent] = append(children[parent], t)
		if p, ok := layers[parent]; ok {
			s.(*shadowNodeDiffLayer).parent = p
		} else if parent == diskLayer.Root() {
			s.(*shadowNodeDiffLayer).parent = diskLayer
		} else {
			return nil, nil, errors.New("cannot found the snap's parent")
		}
	}
	return layers, children, nil
}

type shadowNodeDiffLayer struct {
	blockNumber *big.Int
	blockRoot   common.Hash
	parent      shadowNodeSnapshot
	nodeSet     map[common.Hash]map[string][]byte

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

func (s *shadowNodeDiffLayer) ShadowNode(addrHash common.Hash, prefix string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	cm, exist := s.nodeSet[addrHash]
	if !exist {
		return nil, errors.New("cannot find the address")
	}

	ret, exist := cm[prefix]
	if exist {
		return ret, nil
	}
	return s.parent.ShadowNode(addrHash, prefix)
}

func (s *shadowNodeDiffLayer) Parent() shadowNodeSnapshot {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.parent
}

func (s *shadowNodeDiffLayer) Update(blockNumber *big.Int, blockRoot common.Hash, nodeSet map[common.Hash]map[string][]byte) (shadowNodeSnapshot, error) {
	s.lock.RLock()
	if s.blockNumber.Cmp(blockNumber) < 0 {
		return nil, errors.New("update a unordered diff layer")
	}
	s.lock.RUnlock()
	return newShadowNodeDiffLayer(blockNumber, blockRoot, s, nodeSet), nil
}

func (s *shadowNodeDiffLayer) Journal(buffer *bytes.Buffer) (common.Hash, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

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

type journalShadowNode struct {
	Hash common.Hash
	Keys []string
	Vals [][]byte
}

type shadowNodeDiskLayer struct {
	// TODO(0xbundler): add history & changeSet later
	diskdb      ethdb.KeyValueReader
	blockNumber *big.Int
	blockRoot   common.Hash
	cache       map[common.Hash]map[string][]byte

	lock sync.RWMutex
}

func newShadowNodeDiskLayer(diskdb ethdb.KeyValueReader, blockNumber *big.Int, blockRoot common.Hash) (*shadowNodeDiskLayer, error) {
	return &shadowNodeDiskLayer{
		diskdb:      diskdb,
		blockNumber: blockNumber,
		blockRoot:   blockRoot,
		cache:       make(map[common.Hash]map[string][]byte),
	}, nil
}

func (s *shadowNodeDiskLayer) Root() common.Hash {
	return s.blockRoot
}

func (s *shadowNodeDiskLayer) ShadowNode(addrHash common.Hash, path string) ([]byte, error) {
	nodeSet, exist := s.cache[addrHash]
	if exist {
		if enc, ok := nodeSet[path]; ok {
			return enc, nil
		}
	}
	//TODO(0xbundler): return history & changeSet later
	s.cache[addrHash] = make(map[string][]byte)
	n := shadowBranchNode{
		ShadowHash: common.Hash{},
		EpochMap:   [16]types.StateEpoch{},
	}
	enc, err := rlp.EncodeToBytes(n)
	if err != nil {
		return nil, err
	}
	s.cache[addrHash][path] = enc
	return enc, nil
}

func (s *shadowNodeDiskLayer) Parent() shadowNodeSnapshot {
	return nil
}

func (s *shadowNodeDiskLayer) Update(blockNumber *big.Int, blockRoot common.Hash, nodeSet map[common.Hash]map[string][]byte) (shadowNodeSnapshot, error) {
	s.lock.RLock()
	if s.blockNumber.Cmp(blockNumber) < 0 {
		return nil, errors.New("update a unordered diff layer")
	}
	s.lock.RUnlock()
	return newShadowNodeDiffLayer(blockNumber, blockRoot, s, nodeSet), nil
}

func (s *shadowNodeDiskLayer) Journal(buffer *bytes.Buffer) (common.Hash, error) {
	return common.Hash{}, nil
}
