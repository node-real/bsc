package snapshot

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

const (
	ContractSnapshotAvgSize = 17 // This is an estimated value
)

// ShrinkExpiredLeaf tool function for snapshot kv prune
func ShrinkExpiredLeaf(writer ethdb.KeyValueWriter, reader ethdb.KeyValueReader, accountHash common.Hash, storageHash common.Hash, cfg *types.StateExpiryConfig) (int64, error) {
	if types.StateExpiryPruneLevel1 == cfg.PruneLevel {
		return 0, nil
	}

	rawdb.DeleteStorageSnapshot(writer, accountHash, storageHash)
	return ContractSnapshotAvgSize, nil
}
