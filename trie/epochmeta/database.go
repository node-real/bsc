package epochmeta

import (
	"fmt"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"math/big"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const (
	AccountMetadataPath = "m"
)

var (
	metaAccessMeter       = metrics.NewRegisteredMeter("epochmeta/access", nil)
	metaHitDiffMeter      = metrics.NewRegisteredMeter("epochmeta/access/hit/diff", nil)
	metaHitDiskCacheMeter = metrics.NewRegisteredMeter("epochmeta/access/hit/diskcache", nil)
	metaHitDiskMeter      = metrics.NewRegisteredMeter("epochmeta/access/hit/disk", nil)
)

type BranchNodeEpochMeta struct {
	EpochMap [16]types.StateEpoch
}

func NewBranchNodeEpochMeta(epochMap [16]types.StateEpoch) *BranchNodeEpochMeta {
	return &BranchNodeEpochMeta{EpochMap: epochMap}
}

func (n *BranchNodeEpochMeta) Encode(w rlp.EncoderBuffer) {
	offset := w.List()
	for _, e := range n.EpochMap {
		w.WriteUint64(uint64(e))
	}
	w.ListEnd(offset)
}

func DecodeFullNodeEpochMeta(enc []byte) (*BranchNodeEpochMeta, error) {
	var n BranchNodeEpochMeta

	if err := rlp.DecodeBytes(enc, &n.EpochMap); err != nil {
		return nil, err
	}

	return &n, nil
}

type Reader struct {
	snap snapshot
	tree *SnapshotTree
}

// NewReader first find snap by blockRoot, if got nil, try using number to instance a read only storage
func NewReader(tree *SnapshotTree, number *big.Int, blockRoot common.Hash) (*Reader, error) {
	snap := tree.Snapshot(blockRoot)
	if snap == nil {
		// try using default snap
		if snap = tree.Snapshot(types.EmptyRootHash); snap == nil {
			return nil, fmt.Errorf("cannot find target epoch layer %#x", blockRoot)
		}
		log.Debug("NewReader use default database", "number", number, "root", blockRoot)
	}
	return &Reader{
		snap: snap,
		tree: tree,
	}, nil
}

func (s *Reader) Get(addr common.Hash, path string) ([]byte, error) {
	metaAccessMeter.Mark(1)
	return s.snap.EpochMeta(addr, path)
}
