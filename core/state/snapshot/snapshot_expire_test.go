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

func TestShrinkExpiredLeaf(t *testing.T) {
	db := memorydb.New()
	rawdb.WriteStorageSnapshot(db, accountHash, storageHash1, encodeSnapVal(NewRawValue([]byte("val1"))))

	_, err := ShrinkExpiredLeaf(db, db, accountHash, storageHash1, types.StateEpoch0, rawdb.PathScheme)
	assert.NoError(t, err)

	assert.Equal(t, encodeSnapVal(NewValueWithEpoch(types.StateEpoch0, nil)), rawdb.ReadStorageSnapshot(db, accountHash, storageHash1))
}

func encodeSnapVal(val SnapValue) []byte {
	enc, _ := EncodeValueToRLPBytes(val)
	return enc
}
