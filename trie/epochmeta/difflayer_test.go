package epochmeta

import (
	"github.com/ethereum/go-ethereum/core/types"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/stretchr/testify/assert"
)

const hashLen = len(common.Hash{})

var (
	blockRoot0   = makeHash("b0")
	blockRoot1   = makeHash("b1")
	blockRoot2   = makeHash("b2")
	blockRoot3   = makeHash("b3")
	storageRoot0 = makeHash("s0")
	storageRoot1 = makeHash("s1")
	storageRoot2 = makeHash("s2")
	storageRoot3 = makeHash("s3")
	contract1    = makeHash("c1")
	contract2    = makeHash("c2")
	contract3    = makeHash("c3")
)

func TestEpochMetaDiffLayer_whenGenesis(t *testing.T) {
	diskdb := memorydb.New()
	// create empty tree
	tree, err := NewEpochMetaSnapTree(diskdb, nil)
	assert.NoError(t, err)
	snap := tree.Snapshot(blockRoot0)
	assert.Nil(t, snap)
	snap = tree.Snapshot(blockRoot1)
	assert.Nil(t, snap)
	err = tree.Update(blockRoot0, common.Big1, blockRoot1, makeNodeSet(contract1, []string{"hello", "world"}))
	assert.NoError(t, err)
	err = tree.Update(blockRoot1, common.Big2, blockRoot2, makeNodeSet(contract1, []string{"hello2", "world2"}))
	assert.NoError(t, err)
	err = tree.Cap(blockRoot1)
	assert.NoError(t, err)
	err = tree.Journal()
	assert.NoError(t, err)

	// reload
	tree, err = NewEpochMetaSnapTree(diskdb, nil)
	assert.NoError(t, err)
	diskLayer := tree.Snapshot(types.EmptyRootHash)
	assert.NotNil(t, diskLayer)
	snap = tree.Snapshot(blockRoot0)
	assert.Nil(t, snap)
	snap1 := tree.Snapshot(blockRoot1)
	n, err := snap1.EpochMeta(contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte("world"), n)
	assert.Equal(t, diskLayer, snap1.Parent())
	assert.Equal(t, blockRoot1, snap1.Root())

	// read from child
	snap2 := tree.Snapshot(blockRoot2)
	assert.Equal(t, snap1, snap2.Parent())
	assert.Equal(t, blockRoot2, snap2.Root())
	n, err = snap2.EpochMeta(contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte("world"), n)
	n, err = snap2.EpochMeta(contract1, "hello2")
	assert.NoError(t, err)
	assert.Equal(t, []byte("world2"), n)
}

func TestEpochMetaDiffLayer_crud(t *testing.T) {
	diskdb := memorydb.New()
	// create empty tree
	tree, err := NewEpochMetaSnapTree(diskdb, nil)
	assert.NoError(t, err)
	set1 := makeNodeSet(contract1, []string{"hello", "world", "h1", "w1"})
	appendNodeSet(set1, contract3, []string{"h3", "w3"})
	err = tree.Update(blockRoot0, common.Big1, blockRoot1, set1)
	assert.NoError(t, err)
	set2 := makeNodeSet(contract1, []string{"hello", "", "h1", ""})
	appendNodeSet(set2, contract2, []string{"hello", "", "h2", "w2"})
	err = tree.Update(blockRoot1, common.Big2, blockRoot2, set2)
	assert.NoError(t, err)
	snap := tree.Snapshot(blockRoot1)
	assert.NotNil(t, snap)
	val, err := snap.EpochMeta(contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte("world"), val)
	val, err = snap.EpochMeta(contract1, "h1")
	assert.NoError(t, err)
	assert.Equal(t, []byte("w1"), val)
	val, err = snap.EpochMeta(contract3, "h3")
	assert.NoError(t, err)
	assert.Equal(t, []byte("w3"), val)

	snap = tree.Snapshot(blockRoot2)
	assert.NotNil(t, snap)
	val, err = snap.EpochMeta(contract1, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte{}, val)
	val, err = snap.EpochMeta(contract1, "h1")
	assert.NoError(t, err)
	assert.Equal(t, []byte{}, val)
	val, err = snap.EpochMeta(contract2, "hello")
	assert.NoError(t, err)
	assert.Equal(t, []byte{}, val)
	val, err = snap.EpochMeta(contract2, "h2")
	assert.NoError(t, err)
	assert.Equal(t, []byte("w2"), val)
	val, err = snap.EpochMeta(contract3, "h3")
	assert.NoError(t, err)
	assert.Equal(t, []byte("w3"), val)
}

func makeHash(s string) common.Hash {
	var ret common.Hash
	if len(s) >= 32 {
		copy(ret[:], []byte(s)[:hashLen])
		return ret
	}
	for i := 0; i < hashLen; i++ {
		ret[i] = '0'
	}
	copy(ret[hashLen-len(s):hashLen], s)
	return ret
}

func makeNodeSet(addr common.Hash, kvs []string) map[common.Hash]map[string][]byte {
	if len(kvs)%2 != 0 {
		panic("makeNodeSet: wrong params")
	}
	ret := make(map[common.Hash]map[string][]byte)
	ret[addr] = make(map[string][]byte)
	for i := 0; i < len(kvs); i += 2 {
		if len(kvs) == 0 {
			ret[addr][kvs[i]] = nil
			continue
		}
		ret[addr][kvs[i]] = []byte(kvs[i+1])
	}

	return ret
}

func appendNodeSet(ret map[common.Hash]map[string][]byte, addr common.Hash, kvs []string) {
	if len(kvs)%2 != 0 {
		panic("makeNodeSet: wrong params")
	}
	if _, ok := ret[addr]; !ok {
		ret[addr] = make(map[string][]byte)
	}
	for i := 0; i < len(kvs); i += 2 {
		if len(kvs) == 0 {
			ret[addr][kvs[i]] = nil
			continue
		}
		ret[addr][kvs[i]] = []byte(kvs[i+1])
	}
}
