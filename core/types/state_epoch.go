package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

var (
	StateEpoch0 = StateEpoch(0)
	StateEpoch1 = StateEpoch(1)
)

type StateEpoch uint16

// GetStateEpoch computes the current state epoch by hard fork and block number
// state epoch will indicate if the state is accessible or expiry.
// Before ClaudeBlock indicates state epoch0.
// ClaudeBlock indicates start state epoch1.
// ElwoodBlock indicates start state epoch2 and start epoch rotate by StateEpochPeriod.
// When N>=2 and epochN started, epoch(N-2)'s state will expire.
func GetStateEpoch(config *params.ChainConfig, blockNumber *big.Int) StateEpoch {
	if config.IsElwood(blockNumber) {
		epochPeriod := new(big.Int).SetUint64(config.Parlia.StateEpochPeriod)
		ret := new(big.Int).Sub(blockNumber, config.ElwoodBlock)
		ret.Div(ret, epochPeriod)
		ret.Add(ret, common.Big2)
		return StateEpoch(ret.Uint64())
	} else if config.IsClaude(blockNumber) {
		return 1
	} else {
		return 0
	}
}

// EpochExpired check pre epoch if expired compared to current epoch
func EpochExpired(pre StateEpoch, cur StateEpoch) bool {
	return cur >= 2 && pre < cur-1
}
