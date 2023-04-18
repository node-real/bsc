package trie

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
)

type ShadowNodeStorage interface {
	// Get key is the shadow node prefix path
	Get(key []byte) ([]byte, error)
	Put(key []byte, val []byte) error
	Commit(root common.Hash) error
}

type ShadowNodeManager struct {
	diskdb ethdb.KeyValueStore
	// TODO diff layers
	// TODO history states
}

// NewShadowNodeManager TODO need reload diff layers and rebuild history metadata
func NewShadowNodeManager(diskdb ethdb.KeyValueStore) *ShadowNodeManager {
	return &ShadowNodeManager{
		diskdb: diskdb,
	}
}

//// OpenStorage parentRoot is block root? or contract root ? later save block history?
//func (s *ShadowNodeManager) OpenStorage(parentRoot, addrHash common.Hash) ShadowNodeStorage {
//	// TODO allow RW append on diff layer, only read plainState
//	return &shadowNodeStorageReaderWriterMock{
//		s:          s,
//		parentRoot: parentRoot,
//		addrHash:   addrHash,
//	}
//}

//func (s *ShadowNodeManager) OpenHistoryStorage(blockAt uint64, addrHash common.Hash) ShadowNodeStorage {
//	// TODO only allow read when access history
//}

type shadowNodeStorageReaderWriterMock struct {
	mockEpoch uint16
	nodeMap   map[string][]byte
}

func newShadowNodeStorageMock(epoch uint16) ShadowNodeStorage {
	return &shadowNodeStorageReaderWriterMock{
		mockEpoch: epoch,
		nodeMap:   make(map[string][]byte),
	}
}

func (s *shadowNodeStorageReaderWriterMock) Get(key []byte) ([]byte, error) {
	var err error
	tmp := string(key)
	val, ok := s.nodeMap[tmp]
	if !ok {
		n := shadowBranchNode{
			ShadowHash: nil,
			EpochMap:   [16]uint16{},
		}
		for i := range n.EpochMap {
			n.EpochMap[i] = s.mockEpoch
		}
		val, err = rlp.EncodeToBytes(n)
		if err != nil {
			return nil, err
		}
		s.nodeMap[tmp] = val
	}
	return val, nil
}

func (s *shadowNodeStorageReaderWriterMock) Put(key []byte, val []byte) error {
	s.nodeMap[string(key)] = val
	return nil
}

func (s *shadowNodeStorageReaderWriterMock) Commit(root common.Hash) error {
	return nil
}
