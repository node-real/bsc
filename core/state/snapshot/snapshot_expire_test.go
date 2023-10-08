package snapshot

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	accountHash      = common.HexToHash("0x31b67165f56d0ac50814cafa06748fb3b8fccd3c611a8117350e7a49b44ce130")
	storageHash1     = common.HexToHash("0x0bb2f3e66816c6fd12513f053d5ee034b1fa2d448a1dc8ee7f56e4c87d6c53fe")
	storageHash2     = common.HexToHash("0x0bb2f3e66816c93e142cd336c411ebd5576a90739bad7ec1ec0d4a63ea0ec1dc")
	storageShrink1   = common.FromHex("0x0bb2f3e66816c")
	storageNodeHash1 = common.HexToHash("0xcf0e24cb9417a38ff61d11def23fb0ec041257c81c04dec6156d5e6b30f4ec28")
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
