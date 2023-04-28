package trie

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/stretchr/testify/assert"
)

func TestShadowNodeRW_CRUD(t *testing.T) {
	diskdb := memorydb.New()
	tree, err := NewShadowNodeSnapTree(diskdb)
	assert.NoError(t, err)
	storageRW, err := NewShadowNodeStorageRW(tree, blockRoot1)
	assert.NoError(t, err)

	err = storageRW.Put(contract1, "hello", []byte("world"))
	assert.NoError(t, err)
	err = storageRW.Put(contract1, "hello", []byte("world"))
	assert.NoError(t, err)
	val, err := storageRW.Get(contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte("world"), val)
	err = storageRW.Delete(contract1, "hello")
	assert.NoError(t, err)
	val, err = storageRW.Get(contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte(nil), val)
}

func TestShadowNodeRW_Commit(t *testing.T) {
	diskdb := memorydb.New()
	tree, err := NewShadowNodeSnapTree(diskdb)
	assert.NoError(t, err)
	storageRW, err := NewShadowNodeStorageRW(tree, blockRoot1)
	assert.NoError(t, err)

	err = storageRW.Put(contract1, "hello", []byte("world"))
	assert.NoError(t, err)

	err = storageRW.Commit(common.Big1, blockRoot1)
	assert.NoError(t, err)

	storageRW, err = NewShadowNodeStorageRW(tree, blockRoot1)
	assert.NoError(t, err)
	val, err := storageRW.Get(contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte("world"), val)
}

func TestNewShadowNodeStorage4Trie(t *testing.T) {
	diskdb := memorydb.New()
	tree, err := NewShadowNodeSnapTree(diskdb)
	assert.NoError(t, err)
	storageRW, err := NewShadowNodeStorageRW(tree, blockRoot1)
	assert.NoError(t, err)

	s1 := storageRW.OpenStorage(contract1)
	s2 := storageRW.OpenStorage(contract2)
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

	err = storageRW.Commit(common.Big1, blockRoot2)
	assert.NoError(t, err)
}
