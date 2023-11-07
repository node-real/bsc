package snapshot

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/stretchr/testify/assert"
)

var (
	accountHash  = common.HexToHash("0x31b67165f56d0ac50814cafa06748fb3b8fccd3c611a8117350e7a49b44ce130")
	storageHash1 = common.HexToHash("0x0bb2f3e66816c6fd12513f053d5ee034b1fa2d448a1dc8ee7f56e4c87d6c53fe")
)

func TestShrinkExpiredLeaf_Level1(t *testing.T) {
	db := memorydb.New()
	rawdb.WriteStorageSnapshot(db, accountHash, storageHash1, encodeSnapVal(NewRawValue([]byte("val1"))))

	cfg := &types.StateExpiryConfig{
		StateScheme: rawdb.PathScheme,
		PruneLevel:  types.StateExpiryPruneLevel0,
	}

	_, err := ShrinkExpiredLeaf(db, db, accountHash, storageHash1, cfg)
	assert.NoError(t, err)

	assert.True(t, len(rawdb.ReadStorageSnapshot(db, accountHash, storageHash1)) == 0)
}

func TestShrinkExpiredLeaf_Level0(t *testing.T) {
	db := memorydb.New()
	raw := encodeSnapVal(NewRawValue([]byte("val1")))
	rawdb.WriteStorageSnapshot(db, accountHash, storageHash1, raw)

	cfg := &types.StateExpiryConfig{
		StateScheme: rawdb.PathScheme,
		PruneLevel:  types.StateExpiryPruneLevel1,
	}

	_, err := ShrinkExpiredLeaf(db, db, accountHash, storageHash1, cfg)
	assert.NoError(t, err)

	assert.Equal(t, raw, rawdb.ReadStorageSnapshot(db, accountHash, storageHash1))
}

func encodeSnapVal(val SnapValue) []byte {
	enc, _ := EncodeValueToRLPBytes(val)
	return enc
}
