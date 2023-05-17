package trie

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/stretchr/testify/assert"
)

func TestShadowNodeRW_CRUD(t *testing.T) {
	diskdb := memorydb.New()
	tree, err := NewShadowNodeSnapTree(diskdb, true)
	assert.NoError(t, err)
	storageDB, err := NewShadowNodeDatabase(tree, common.Big1, blockRoot1)
	assert.NoError(t, err)

	err = storageDB.Put(contract1, "hello", []byte("world"))
	assert.NoError(t, err)
	err = storageDB.Put(contract1, "hello", []byte("world"))
	assert.NoError(t, err)
	val, err := storageDB.Get(contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte("world"), val)
	err = storageDB.Delete(contract1, "hello")
	assert.NoError(t, err)
	val, err = storageDB.Get(contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte(nil), val)
}

func TestShadowNodeRO_Get(t *testing.T) {
	diskdb := memorydb.New()
	makeDiskLayer(diskdb, common.Big2, blockRoot2, contract1, []string{"k1", "v1"})

	tree, err := NewShadowNodeSnapTree(diskdb, true)
	assert.NoError(t, err)
	storageRO, err := NewShadowNodeDatabase(tree, common.Big1, blockRoot1)
	assert.NoError(t, err)

	err = storageRO.Put(contract1, "hello", []byte("world"))
	assert.Error(t, err)
	err = storageRO.Delete(contract1, "hello")
	assert.Error(t, err)
	err = storageRO.Commit(common.Big2, blockRoot2)
	assert.Error(t, err)

	val, err := storageRO.Get(contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte(nil), val)
	val, err = storageRO.Get(contract1, "k1")
	assert.NoError(t, err)
	assert.Equal(t, []byte("v1"), val)
}

func makeDiskLayer(diskdb *memorydb.Database, number *big.Int, root common.Hash, addr common.Hash, kv []string) {
	if len(kv)%2 != 0 {
		panic("wrong kv")
	}
	meta := shadowNodePlainMeta{
		BlockNumber: number,
		BlockRoot:   root,
	}
	enc, _ := rlp.EncodeToBytes(&meta)
	rawdb.WriteShadowNodePlainStateMeta(diskdb, enc)

	for i := 0; i < len(kv); i += 2 {
		rawdb.WriteShadowNodePlainState(diskdb, addr, kv[i], []byte(kv[i+1]))
	}
}

func TestShadowNodeRW_Commit(t *testing.T) {
	diskdb := memorydb.New()
	tree, err := NewShadowNodeSnapTree(diskdb, true)
	assert.NoError(t, err)
	storageDB, err := NewShadowNodeDatabase(tree, common.Big1, blockRoot1)
	assert.NoError(t, err)

	err = storageDB.Put(contract1, "hello", []byte("world"))
	assert.NoError(t, err)

	err = storageDB.Commit(common.Big1, blockRoot1)
	assert.NoError(t, err)

	storageDB, err = NewShadowNodeDatabase(tree, common.Big1, blockRoot1)
	assert.NoError(t, err)
	val, err := storageDB.Get(contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte("world"), val)
}

func TestNewShadowNodeStorage4Trie(t *testing.T) {
	diskdb := memorydb.New()
	tree, err := NewShadowNodeSnapTree(diskdb, true)
	assert.NoError(t, err)
	storageDB, err := NewShadowNodeDatabase(tree, common.Big1, blockRoot1)
	assert.NoError(t, err)

	s1 := storageDB.OpenStorage(contract1)
	s2 := storageDB.OpenStorage(contract2)
	val, err := s1.Get("hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte(nil), val)
	err = s1.Put("hello", []byte("world"))
	assert.NoError(t, err)
	val, _ = s1.Get("hello")
	assert.Equal(t, []byte("world"), val)
	val, _ = s2.Get("hello")
	assert.Equal(t, []byte(nil), val)
	err = s1.Delete("hello")
	assert.NoError(t, err)
	val, _ = s1.Get("hello")
	assert.Equal(t, []byte(nil), val)

	s2.Put("h2", []byte("w2"))
	val, _ = s2.Get("h2")
	assert.Equal(t, []byte("w2"), val)

	err = storageDB.Commit(common.Big1, blockRoot2)
	assert.NoError(t, err)
}

func TestShadowExtendNode_encodeDecode(t *testing.T) {
	dt := []struct {
		n shadowExtensionNode
	}{
		{
			n: shadowExtensionNode{
				ShadowHash: nil,
			},
		},
		{
			n: shadowExtensionNode{
				ShadowHash: &blockRoot0,
			},
		},
		{
			n: shadowExtensionNode{
				ShadowHash: &blockRoot1,
			},
		},
	}
	for _, item := range dt {
		buf := rlp.NewEncoderBuffer(bytes.NewBuffer([]byte{}))
		item.n.encode(buf)
		enc := buf.ToBytes()

		rn, err := decodeShadowExtensionNode(enc)
		assert.NoError(t, err)
		assert.Equal(t, &item.n, rn)
	}
}

func TestShadowBranchNode_encodeDecode(t *testing.T) {
	dt := []struct {
		n shadowBranchNode
	}{
		{
			n: shadowBranchNode{
				ShadowHash: nil,
				EpochMap:   [16]types.StateEpoch{},
			},
		},
		{
			n: shadowBranchNode{
				ShadowHash: nil,
				EpochMap:   [16]types.StateEpoch{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
		},
		{
			n: shadowBranchNode{
				ShadowHash: &blockRoot0,
				EpochMap:   [16]types.StateEpoch{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
		},
		{
			n: shadowBranchNode{
				ShadowHash: &blockRoot1,
				EpochMap:   [16]types.StateEpoch{},
			},
		},
	}
	for _, item := range dt {
		buf := rlp.NewEncoderBuffer(bytes.NewBuffer([]byte{}))
		item.n.encode(buf)
		enc := buf.ToBytes()

		rn, err := decodeShadowBranchNode(enc)
		assert.NoError(t, err)
		assert.Equal(t, &item.n, rn)
	}
}

func TestRootNode_encodeDecode(t *testing.T) {
	dt := []struct {
		n       rootNode
		isEqual bool
	}{
		{
			n: rootNode{
				Epoch:          10,
				TrieRoot:       blockRoot0,
				ShadowTreeRoot: blockRoot1,
			},
			isEqual: true,
		},
		{
			n:       rootNode{},
			isEqual: true,
		},
		{
			n: rootNode{
				Epoch:          100,
				TrieRoot:       blockRoot2,
				ShadowTreeRoot: common.Hash{},
			},
			isEqual: true,
		},
		{
			n: rootNode{},
		},
	}

	for _, item := range dt {
		item.n.resolveCache()
		buf := rlp.NewEncoderBuffer(bytes.NewBuffer([]byte{}))
		item.n.encode(buf)
		enc := buf.ToBytes()

		rn, err := decodeRootNode(enc)
		assert.NoError(t, err)
		if !item.isEqual {
			assert.NotEqual(t, item.n, rn)
			continue
		}
		assert.Equal(t, &item.n, rn)
	}
}
