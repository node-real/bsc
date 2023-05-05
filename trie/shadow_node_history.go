package trie

import (
	"bytes"
	"errors"

	"github.com/RoaringBitmap/roaring/roaring64"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
)

func FindHistory(db ethdb.KeyValueStore, number uint64, addr common.Hash, path string) ([]byte, error) {
	val, found, err := findHistory(db, number, addr, path)
	if err != nil {
		return nil, err
	}

	if found {
		return val, nil
	}

	// query from plain state
	return rawdb.ReadShadowNodePlainState(db, addr, path), nil
}

type nodeChgRecord struct {
	Path string
	Prev []byte
}

func findHistory(db ethdb.KeyValueStore, number uint64, addr common.Hash, path string) ([]byte, bool, error) {
	// TODO(0xbundler): split shards according bitmap size later, less than 1mb
	hbytes := rawdb.ReadShadowNodeHistory(db, addr, path, math.MaxUint64)
	if len(hbytes) == 0 {
		return nil, false, nil
	}

	index := roaring64.New()
	if _, err := index.ReadFrom(bytes.NewReader(hbytes)); err != nil {
		return nil, false, err
	}
	found, ok := SeekInBitmap64(index, number)
	if !ok {
		return nil, false, nil
	}

	// TODO(0xbundler): using mdbx's DupSort?
	changeSet := rawdb.ReadShadowNodeChangeSet(db, addr, found)
	if len(changeSet) == 0 {
		return nil, false, errors.New("cannot find target changeSet")
	}
	var ns []nodeChgRecord
	if err := rlp.DecodeBytes(changeSet, &ns); err != nil {
		return nil, false, err
	}
	nodeSetMap := make(map[string][]byte)
	for _, n := range ns {
		nodeSetMap[n.Path] = n.Prev
	}

	val, exist := nodeSetMap[path]
	if !exist {
		return nil, false, errors.New("cannot find path's change val")
	}

	return val, true, nil
}

// SeekInBitmap - returns value in bitmap which is >= n
func SeekInBitmap64(m *roaring64.Bitmap, n uint64) (found uint64, ok bool) {
	if m.IsEmpty() {
		return 0, false
	}
	if n == 0 {
		return m.Minimum(), true
	}
	searchRank := m.Rank(n - 1)
	if searchRank >= m.GetCardinality() {
		return 0, false
	}
	found, _ = m.Select(searchRank)
	return found, true
}
