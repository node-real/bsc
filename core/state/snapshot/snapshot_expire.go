package snapshot

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

// ShrinkExpiredLeaf tool function for snapshot kv prune
func ShrinkExpiredLeaf(db ethdb.KeyValueWriter, accountHash common.Hash, storageHash common.Hash, epoch types.StateEpoch, scheme string) error {
	switch scheme {
	case rawdb.HashScheme:
		//cannot prune snapshot in hbss, because it will used for trie prune, but it's ok in pbss.
	case rawdb.PathScheme:
		valWithEpoch := NewValueWithEpoch(epoch, nil)
		enc, err := EncodeValueToRLPBytes(valWithEpoch)
		if err != nil {
			return err
		}
		rawdb.WriteStorageSnapshot(db, accountHash, storageHash, enc)
	}
	return nil
}
