package trie

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/stretchr/testify/assert"
)

func TestShadowNodeHistory_Diff2Disk(t *testing.T) {
	diskdb := memorydb.New()
	diskLayer, err := loadDiskLayer(diskdb)
	assert.NoError(t, err)
	diff := newShadowNodeDiffLayer(common.Big1, blockRoot1, nil, makeNodeSet(contract1, []string{"hello", "world"}))
	_, err = diskLayer.PushDiff(diff)
	assert.NoError(t, err)

	// find history
	val, err := FindHistory(diskdb, common.Big2.Uint64(), contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte("world"), val)
	val, err = FindHistory(diskdb, common.Big1.Uint64(), contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte{}, val)

	// reload disk layer
	diskLayer, err = loadDiskLayer(diskdb)
	assert.NoError(t, err)
	val, err = diskLayer.ShadowNode(contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte("world"), val)
}

func TestShadowNodeHistory_case2(t *testing.T) {
	diskdb := memorydb.New()
	diskLayer, err := loadDiskLayer(diskdb)
	assert.NoError(t, err)

	diff := newShadowNodeDiffLayer(common.Big1, blockRoot1, nil, makeNodeSet(contract1, []string{"hello", "world"}))
	diskLayer, err = diskLayer.PushDiff(diff)
	assert.NoError(t, err)

	diff = newShadowNodeDiffLayer(common.Big2, blockRoot2, nil, makeNodeSet(contract1, []string{"hello", "world1"}))
	diskLayer, err = diskLayer.PushDiff(diff)
	assert.NoError(t, err)

	val, err := FindHistory(diskdb, common.Big2.Uint64(), contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte("world"), val)

	val, err = FindHistory(diskdb, common.Big3.Uint64(), contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte("world1"), val)
}
