package epochmeta

import (
	"bytes"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	lru "github.com/hashicorp/golang-lru"
	"math/big"
	"sync"
)

const (
	defaultDiskLayerCacheSize = 100000
)

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

	key := cacheKey(addr, path)
	cached, exist := s.cache.Get(key)
	if exist {
		metaHitDiskCacheMeter.Mark(1)
		return cached.([]byte), nil
	}

	metaHitDiskMeter.Mark(1)
	val := rawdb.ReadEpochMetaPlainState(s.diskdb, addr, path)
	s.cache.Add(key, val)
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
	if err := s.writeHistory(number, batch, nodeSet); err != nil {
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
