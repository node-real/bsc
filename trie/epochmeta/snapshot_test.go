package epochmeta

import (
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/stretchr/testify/assert"
	"math/big"
	"strconv"
	"testing"
)

func TestEpochMetaDiffLayer_capDiffLayers(t *testing.T) {
	diskdb := memorydb.New()
	// create empty tree
	tree, err := NewEpochMetaSnapTree(diskdb, nil)
	assert.NoError(t, err)

	// push 200 diff layers
	count := 1
	for i := 0; i < 200; i++ {
		ns := strconv.Itoa(count)
		root := makeHash("b" + ns)
		parent := makeHash("b" + strconv.Itoa(count-1))
		number := new(big.Int).SetUint64(uint64(count))
		err = tree.Update(parent, number,
			root, makeNodeSet(contract1, []string{"hello" + ns, "world" + ns}))
		assert.NoError(t, err)

		// add 10 forks
		for j := 0; j < 10; j++ {
			fs := strconv.Itoa(j)
			err = tree.Update(parent, number,
				makeHash("b"+ns+"f"+fs), makeNodeSet(contract1, []string{"hello" + ns + "f" + fs, "world" + ns + "f" + fs}))
			assert.NoError(t, err)
		}

		err = tree.Cap(root)
		assert.NoError(t, err)
		count++
	}
	assert.Equal(t, 1409, len(tree.layers))

	// push 100 diff layers, and cap
	for i := 0; i < 100; i++ {
		ns := strconv.Itoa(count)
		parent := makeHash("b" + strconv.Itoa(count-1))
		root := makeHash("b" + ns)
		number := new(big.Int).SetUint64(uint64(count))
		err = tree.Update(parent, number, root,
			makeNodeSet(contract1, []string{"hello" + ns, "world" + ns}))
		assert.NoError(t, err)

		// add 20 forks
		for j := 0; j < 10; j++ {
			fs := strconv.Itoa(j)
			err = tree.Update(parent, number,
				makeHash("b"+ns+"f"+fs), makeNodeSet(contract1, []string{"hello" + ns + "f" + fs, "world" + ns + "f" + fs}))
			assert.NoError(t, err)
		}
		for j := 0; j < 10; j++ {
			fs := strconv.Itoa(j)
			err = tree.Update(makeHash("b"+strconv.Itoa(count-1)+"f"+fs), number,
				makeHash("b"+ns+"f"+fs), makeNodeSet(contract1, []string{"hello" + ns + "f" + fs, "world" + ns + "f" + fs}))
			assert.NoError(t, err)
		}
		count++
	}
	lastRoot := makeHash("b" + strconv.Itoa(count-1))
	err = tree.Cap(lastRoot)
	assert.NoError(t, err)
	assert.Equal(t, 1409, len(tree.layers))

	// push 100 diff layers, and cap
	for i := 0; i < 129; i++ {
		ns := strconv.Itoa(count)
		parent := makeHash("b" + strconv.Itoa(count-1))
		root := makeHash("b" + ns)
		number := new(big.Int).SetUint64(uint64(count))
		err = tree.Update(parent, number, root,
			makeNodeSet(contract1, []string{"hello" + ns, "world" + ns}))
		assert.NoError(t, err)

		count++
	}
	lastRoot = makeHash("b" + strconv.Itoa(count-1))
	err = tree.Cap(lastRoot)
	assert.NoError(t, err)

	assert.Equal(t, 129, len(tree.layers))
	assert.Equal(t, 128, len(tree.children))
	for parent, children := range tree.children {
		if tree.layers[parent] == nil {
			t.Log(tree.layers[parent])
		}
		assert.NotNil(t, tree.layers[parent])
		for _, child := range children {
			if tree.layers[child] == nil {
				t.Log(tree.layers[child])
			}
			assert.NotNil(t, tree.layers[child])
		}
	}

	snap := tree.Snapshot(lastRoot)
	assert.NotNil(t, snap)
	for i := 1; i < count; i++ {
		ns := strconv.Itoa(i)
		n, err := snap.EpochMeta(contract1, "hello"+ns)
		assert.NoError(t, err)
		assert.Equal(t, []byte("world"+ns), n)
	}

	// store
	err = tree.Journal()
	assert.NoError(t, err)

	tree, err = NewEpochMetaSnapTree(diskdb, nil)
	assert.NoError(t, err)
	assert.Equal(t, 129, len(tree.layers))
	assert.Equal(t, 128, len(tree.children))
}
