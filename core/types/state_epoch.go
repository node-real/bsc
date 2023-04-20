package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

var (
	// EpochPeriod indicates the state rotate epoch block length
	EpochPeriod = big.NewInt(7_008_000)
	StateEpoch0 = StateEpoch(0)
)

type StateEpoch uint16

// GetStateEpoch computes the current state epoch by hard fork and block number
// state epoch will indicate if the state is accessible or expiry.
// Before ClaudeBlock indicates state epoch0.
// ClaudeBlock indicates start state epoch1.
// ElwoodBlock indicates start state epoch2 and start epoch rotate by EpochPeriod.
// When N>=2 and epochN started, epoch(N-2)'s state will expire.
func GetStateEpoch(config *params.ChainConfig, blockNumber *big.Int) StateEpoch {
	if config.IsElwood(blockNumber) {
		ret := new(big.Int).Sub(blockNumber, config.ElwoodBlock)
		ret.Div(ret, EpochPeriod)
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
