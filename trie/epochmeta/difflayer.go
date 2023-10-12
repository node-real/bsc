package epochmeta

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	bloomfilter "github.com/holiman/bloomfilter/v2"
	"math"
	"math/big"
	"math/rand"
	"sync"
)

const (
	// MaxEpochMetaDiffDepth default is 128 layers
	MaxEpochMetaDiffDepth        = 128
	journalVersion        uint64 = 1
	enableBloomFilter            = false
)

var (
	// aggregatorMemoryLimit is the maximum size of the bottom-most diff layer
	// that aggregates the writes from above until it's flushed into the disk
	// layer.
	//
	// Note, bumping this up might drastically increase the size of the bloom
	// filters that's stored in every diff layer. Don't do that without fully
	// understanding all the implications.
	aggregatorMemoryLimit = uint64(4 * 1024 * 1024)

	// aggregatorItemLimit is an approximate number of items that will end up
	// in the agregator layer before it's flushed out to disk. A plain account
	// weighs around 14B (+hash), a storage slot 32B (+hash), a deleted slot
	// 0B (+hash). Slots are mostly set/unset in lockstep, so that average at
	// 16B (+hash). All in all, the average entry seems to be 15+32=47B. Use a
	// smaller number to be on the safe side.
	aggregatorItemLimit = aggregatorMemoryLimit / 42

	// bloomTargetError is the target false positive rate when the aggregator
	// layer is at its fullest. The actual value will probably move around up
	// and down from this number, it's mostly a ballpark figure.
	//
	// Note, dropping this down might drastically increase the size of the bloom
	// filters that's stored in every diff layer. Don't do that without fully
	// understanding all the implications.
	bloomTargetError = 0.02

	// bloomSize is the ideal bloom filter size given the maximum number of items
	// it's expected to hold and the target false positive error rate.
	bloomSize = math.Ceil(float64(aggregatorItemLimit) * math.Log(bloomTargetError) / math.Log(1/math.Pow(2, math.Log(2))))

	// bloomFuncs is the ideal number of bits a single entry should set in the
	// bloom filter to keep its size to a minimum (given it's size and maximum
	// entry count).
	bloomFuncs = math.Round((bloomSize / float64(aggregatorItemLimit)) * math.Log(2))
	// the bloom offsets are runtime constants which determines which part of the
	// account/storage hash the hasher functions looks at, to determine the
	// bloom key for an account/slot. This is randomized at init(), so that the
	// global population of nodes do not all display the exact same behaviour with
	// regards to bloom content
	bloomStorageHasherOffset = 0
)

func init() {
	// Init the bloom offsets in the range [0:24] (requires 8 bytes)
	bloomStorageHasherOffset = rand.Intn(25)
}

// storageBloomHasher is a wrapper around a [2]common.Hash to satisfy the interface
// API requirements of the bloom library used. It's used to convert an account
// hash into a 64 bit mini hash.
type storageBloomHasher struct {
	accountHash common.Hash
	path        string
}

func (h storageBloomHasher) Write(p []byte) (n int, err error) { panic("not implemented") }
func (h storageBloomHasher) Sum(b []byte) []byte               { panic("not implemented") }
func (h storageBloomHasher) Reset()                            { panic("not implemented") }
func (h storageBloomHasher) BlockSize() int                    { panic("not implemented") }
func (h storageBloomHasher) Size() int                         { return 8 }
func (h storageBloomHasher) Sum64() uint64 {
	if len(h.path) < 8 {
		path := [8]byte{}
		copy(path[:], h.path)
		return binary.BigEndian.Uint64(h.accountHash[bloomStorageHasherOffset:bloomStorageHasherOffset+8]) ^
			binary.BigEndian.Uint64(path[:])
	}
	if len(h.path) < bloomStorageHasherOffset+8 {
		return binary.BigEndian.Uint64(h.accountHash[bloomStorageHasherOffset:bloomStorageHasherOffset+8]) ^
			binary.BigEndian.Uint64([]byte(h.path[len(h.path)-8:]))
	}
	return binary.BigEndian.Uint64(h.accountHash[bloomStorageHasherOffset:bloomStorageHasherOffset+8]) ^
		binary.BigEndian.Uint64([]byte(h.path[bloomStorageHasherOffset:bloomStorageHasherOffset+8]))
}

type diffLayer struct {
	blockNumber *big.Int
	blockRoot   common.Hash
	parent      snapshot
	origin      *diskLayer
	nodeSet     map[common.Hash]map[string][]byte
	diffed      *bloomfilter.Filter // Bloom filter tracking all the diffed items up to the disk layer
	lock        sync.RWMutex        // lock only protect parent filed change now.
}

func newEpochMetaDiffLayer(blockNumber *big.Int, blockRoot common.Hash, parent snapshot, nodeSet map[common.Hash]map[string][]byte) *diffLayer {
	dl := &diffLayer{
		blockNumber: blockNumber,
		blockRoot:   blockRoot,
		parent:      parent,
		nodeSet:     nodeSet,
	}

	if enableBloomFilter {
		switch p := parent.(type) {
		case *diffLayer:
			dl.origin = p.origin
			dl.diffed, _ = p.diffed.Copy()
		case *diskLayer:
			dl.origin = p
			dl.diffed, _ = bloomfilter.New(uint64(bloomSize), uint64(bloomFuncs))
		default:
			panic("newEpochMetaDiffLayer got wrong snapshot type")
		}
		// Iterate over all the accounts and storage metas and index them
		for accountHash, metas := range dl.nodeSet {
			for path := range metas {
				dl.diffed.Add(storageBloomHasher{accountHash, path})
			}
		}
	}

	return dl
}

func (s *diffLayer) Root() common.Hash {
	return s.blockRoot
}

// EpochMeta find target epoch meta from diff layer or disk layer
func (s *diffLayer) EpochMeta(addrHash common.Hash, path string) ([]byte, error) {
	// if the diff chain not contain the meta or staled, try get from disk layer
	if s.diffed != nil && !s.diffed.Contains(storageBloomHasher{addrHash, path}) {
		return s.origin.EpochMeta(addrHash, path)
	}

	cm, exist := s.nodeSet[addrHash]
	if exist {
		if ret, ok := cm[path]; ok {
			metaHitDiffMeter.Mark(1)
			return ret, nil
		}
	}

	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.parent.EpochMeta(addrHash, path)
}

func (s *diffLayer) Parent() snapshot {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.parent
}

// Update append new diff layer onto current, nodeChgRecord when val is []byte{}, it delete the kv
func (s *diffLayer) Update(blockNumber *big.Int, blockRoot common.Hash, nodeSet map[common.Hash]map[string][]byte) (snapshot, error) {
	if s.blockNumber.Int64() != 0 && s.blockNumber.Cmp(blockNumber) >= 0 {
		return nil, errors.New("update a unordered diff layer in diff layer")
	}
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

func (s *diffLayer) getNodeSet() map[common.Hash]map[string][]byte {
	return s.nodeSet
}

func (s *diffLayer) resetParent(parent snapshot) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.parent = parent
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
