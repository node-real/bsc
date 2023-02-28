package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
)

var (
	// EpochPeriod indicates the state rotate epoch block length
	EpochPeriod = big.NewInt(7_008_000)
)

// GetCurrentEpoch computes the current state epoch by hard fork and block number
// state epoch will indicate if the state is accessible or expiry.
// Before ClaudeBlock indicates state epoch0.
// ClaudeBlock indicates start state epoch1.
// ElwoodBlock indicates start state epoch2 and start epoch rotate by EpochPeriod.
// When N>=2 and epochN started, epoch(N-2)'s state will expire.
func GetCurrentEpoch(config *params.ChainConfig, blockNumber *big.Int) *big.Int {
	if config.IsElwood(blockNumber) {
		ret := new(big.Int).Sub(blockNumber, config.ElwoodBlock)
		ret.Div(ret, EpochPeriod)
		ret.Add(ret, common.Big2)
		return ret
	} else if config.IsClaude(blockNumber) {
		return common.Big1
	} else {
		return common.Big0
	}
}
