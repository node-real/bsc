package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

const (
	DefaultStateEpochPeriod = uint64(7_008_000)
	StateEpoch0             = StateEpoch(0)
	StateEpoch1             = StateEpoch(1)
	StateEpochKeepLiveNum   = StateEpoch(2)
)

type StateEpoch uint16

// GetStateEpoch computes the current state epoch by hard fork and block number
// state epoch will indicate if the state is accessible or expiry.
// Before ClaudeBlock indicates state epoch0.
// ClaudeBlock indicates start state epoch1.
// ElwoodBlock indicates start state epoch2 and start epoch rotate by StateEpochPeriod.
// When N>=2 and epochN started, epoch(N-2)'s state will expire.
func GetStateEpoch(config *params.ChainConfig, blockNumber *big.Int) StateEpoch {
	if blockNumber == nil || config == nil {
		return StateEpoch0
	}
	epochPeriod := new(big.Int).SetUint64(DefaultStateEpochPeriod)
	epoch1Block := epochPeriod
	epoch2Block := new(big.Int).Add(epoch1Block, epochPeriod)

	if config.Clique != nil && config.Clique.StateEpochPeriod != 0 {
		epochPeriod = new(big.Int).SetUint64(config.Clique.StateEpochPeriod)
		epoch1Block = new(big.Int).SetUint64(config.Clique.StateEpoch1Block)
		epoch2Block = new(big.Int).SetUint64(config.Clique.StateEpoch2Block)
	}
	if isBlockReached(blockNumber, epoch2Block) {
		ret := new(big.Int).Sub(blockNumber, epoch2Block)
		ret.Div(ret, epochPeriod)
		ret.Add(ret, common.Big2)
		return StateEpoch(ret.Uint64())
	}
	if isBlockReached(blockNumber, epoch1Block) {
		return 1
	}

	return 0
}

// EpochExpired check pre epoch if expired compared to current epoch
func EpochExpired(pre StateEpoch, cur StateEpoch) bool {
	return cur > pre && cur-pre >= StateEpochKeepLiveNum
}

// isBlockReached check if reach expected block number
func isBlockReached(block, expected *big.Int) bool {
	if block == nil || expected == nil {
		return false
	}
	return block.Cmp(expected) >= 0
}
