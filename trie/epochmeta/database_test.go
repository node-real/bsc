package epochmeta

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

func TestEpochMetaRW_CRUD(t *testing.T) {
	diskdb := memorydb.New()
	tree, err := NewEpochMetaSnapTree(diskdb)
	assert.NoError(t, err)
	storageDB, err := NewEpochMetaDatabase(tree, common.Big1, blockRoot1)
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

func TestEpochMetaRO_Get(t *testing.T) {
	diskdb := memorydb.New()
	makeDiskLayer(diskdb, common.Big1, blockRoot1, contract1, []string{"k1", "v1"})

	tree, err := NewEpochMetaSnapTree(diskdb)
	assert.NoError(t, err)
	storageRO, err := NewEpochMetaDatabase(tree, common.Big1, blockRoot1)
	assert.NoError(t, err)

	err = storageRO.Put(contract1, "hello", []byte("world"))
	assert.NoError(t, err)
	err = storageRO.Delete(contract1, "hello")
	assert.NoError(t, err)
	err = storageRO.Commit(common.Big2, blockRoot2)
	assert.NoError(t, err)

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
	meta := epochMetaPlainMeta{
		BlockNumber: number,
		BlockRoot:   root,
	}
	enc, _ := rlp.EncodeToBytes(&meta)
	rawdb.WriteEpochMetaPlainStateMeta(diskdb, enc)

	for i := 0; i < len(kv); i += 2 {
		rawdb.WriteEpochMetaPlainState(diskdb, addr, kv[i], []byte(kv[i+1]))
	}
}

func TestEpochMetaRW_Commit(t *testing.T) {
	diskdb := memorydb.New()
	tree, err := NewEpochMetaSnapTree(diskdb)
	assert.NoError(t, err)
	storageDB, err := NewEpochMetaDatabase(tree, common.Big1, blockRoot1)
	assert.NoError(t, err)

	err = storageDB.Put(contract1, "hello", []byte("world"))
	assert.NoError(t, err)

	err = storageDB.Commit(common.Big1, blockRoot1)
	assert.NoError(t, err)

	storageDB, err = NewEpochMetaDatabase(tree, common.Big1, blockRoot1)
	assert.NoError(t, err)
	val, err := storageDB.Get(contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte("world"), val)
}

func TestShadowBranchNode_encodeDecode(t *testing.T) {
	dt := []struct {
		n BranchNodeEpochMeta
	}{
		{
			n: BranchNodeEpochMeta{
				EpochMap: [16]types.StateEpoch{},
			},
		},
		{
			n: BranchNodeEpochMeta{
				EpochMap: [16]types.StateEpoch{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
		},
		{
			n: BranchNodeEpochMeta{
				EpochMap: [16]types.StateEpoch{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
		},
		{
			n: BranchNodeEpochMeta{
				EpochMap: [16]types.StateEpoch{},
			},
		},
	}
	for _, item := range dt {
		buf := rlp.NewEncoderBuffer(bytes.NewBuffer([]byte{}))
		item.n.Encode(buf)
		enc := buf.ToBytes()

		rn, err := DecodeFullNodeEpochMeta(enc)
		assert.NoError(t, err)
		assert.Equal(t, &item.n, rn)
	}
}
