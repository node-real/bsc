package snapshot

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// ShrinkExpiredLeaf tool function for snapshot kv prune
func ShrinkExpiredLeaf(writer ethdb.KeyValueWriter, reader ethdb.KeyValueReader, accountHash common.Hash, storageHash common.Hash, epoch types.StateEpoch, scheme string) (int64, error) {
	switch scheme {
	case rawdb.HashScheme:
		//cannot prune snapshot in hbss, because it will used for trie prune, but it's ok in pbss.
	case rawdb.PathScheme:
		val := rawdb.ReadStorageSnapshot(reader, accountHash, storageHash)
		if len(val) == 0 {
			log.Debug("cannot find source snapshot?", "addr", accountHash, "key", storageHash, "epoch", epoch)
			return 0, nil
		}
		valWithEpoch := NewValueWithEpoch(epoch, nil)
		enc, err := EncodeValueToRLPBytes(valWithEpoch)
		if err != nil {
			return 0, err
		}
		rawdb.WriteStorageSnapshot(writer, accountHash, storageHash, enc)
		shrinkSize := len(val) - len(enc)
		if shrinkSize < 0 {
			shrinkSize = 0
		}
		return int64(shrinkSize), nil
	}
	return 0, nil
}
