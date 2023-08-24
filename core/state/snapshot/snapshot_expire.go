package snapshot

import (
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

var (
	ErrStorageExpired = errors.New("access expired account storage kv")
)

// ShrinkExpiredLeaf tool function for snapshot kv prune
func ShrinkExpiredLeaf(db ethdb.KeyValueStore, accountHash common.Hash, storageHash common.Hash, epoch types.StateEpoch) error {
	valWithEpoch := NewValueWithEpoch(epoch, nil)
	enc, err := EncodeValueToRLPBytes(valWithEpoch)
	if err != nil {
		return err
	}
	rawdb.WriteStorageSnapshot(db, accountHash, storageHash, enc)
	return nil
}
