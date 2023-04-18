package types

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/assert"
)

func TestStateForkConfig(t *testing.T) {
	temp := &params.ChainConfig{}
	assert.NoError(t, temp.CheckConfigForkOrder())

	temp = &params.ChainConfig{
		ClaudeBlock: big.NewInt(1),
	}
	assert.NoError(t, temp.CheckConfigForkOrder())

	temp = &params.ChainConfig{
		ElwoodBlock: big.NewInt(1),
	}
	assert.Error(t, temp.CheckConfigForkOrder())

	temp = &params.ChainConfig{
		ClaudeBlock: big.NewInt(0),
		ElwoodBlock: big.NewInt(0),
	}
	assert.Error(t, temp.CheckConfigForkOrder())

	temp = &params.ChainConfig{
		ClaudeBlock: big.NewInt(10000),
		ElwoodBlock: big.NewInt(10000),
	}
	assert.Error(t, temp.CheckConfigForkOrder())

	temp = &params.ChainConfig{
		ClaudeBlock: big.NewInt(2),
		ElwoodBlock: big.NewInt(1),
	}
	assert.Error(t, temp.CheckConfigForkOrder())

	temp = &params.ChainConfig{
		ClaudeBlock: big.NewInt(0),
		ElwoodBlock: big.NewInt(1),
	}
	assert.Error(t, temp.CheckConfigForkOrder())

	temp = &params.ChainConfig{
		ClaudeBlock: big.NewInt(10000),
		ElwoodBlock: big.NewInt(10001),
	}
	assert.NoError(t, temp.CheckConfigForkOrder())
}

func TestSimpleStateEpoch(t *testing.T) {
	temp := &params.ChainConfig{
		ClaudeBlock: big.NewInt(10000),
		ElwoodBlock: big.NewInt(20000),
	}
	assert.NoError(t, temp.CheckConfigForkOrder())

	assert.Equal(t, big.NewInt(0), GetCurrentEpoch(temp, big.NewInt(0)))
	assert.Equal(t, big.NewInt(0), GetCurrentEpoch(temp, big.NewInt(1000)))
	assert.Equal(t, big.NewInt(1), GetCurrentEpoch(temp, big.NewInt(10000)))
	assert.Equal(t, big.NewInt(1), GetCurrentEpoch(temp, big.NewInt(19999)))
	assert.Equal(t, big.NewInt(2), GetCurrentEpoch(temp, big.NewInt(20000)))
	assert.Equal(t, big.NewInt(3), GetCurrentEpoch(temp, new(big.Int).Add(big.NewInt(20000), EpochPeriod)))
	assert.Equal(t, big.NewInt(102), GetCurrentEpoch(temp, new(big.Int).Add(big.NewInt(20000), new(big.Int).Mul(big.NewInt(100), EpochPeriod))))
}

func TestNoZeroStateEpoch(t *testing.T) {
	temp := &params.ChainConfig{
		ClaudeBlock: big.NewInt(1),
		ElwoodBlock: big.NewInt(2),
	}
	assert.NoError(t, temp.CheckConfigForkOrder())

	assert.Equal(t, big.NewInt(0), GetCurrentEpoch(temp, big.NewInt(0)))
	assert.Equal(t, big.NewInt(1), GetCurrentEpoch(temp, big.NewInt(1)))
	assert.Equal(t, big.NewInt(2), GetCurrentEpoch(temp, big.NewInt(2)))
	assert.Equal(t, big.NewInt(2), GetCurrentEpoch(temp, big.NewInt(10000)))
	assert.Equal(t, big.NewInt(3), GetCurrentEpoch(temp, new(big.Int).Add(big.NewInt(2), EpochPeriod)))
	assert.Equal(t, big.NewInt(102), GetCurrentEpoch(temp, new(big.Int).Add(big.NewInt(2), new(big.Int).Mul(big.NewInt(100), EpochPeriod))))
}

func TestNearestStateEpoch(t *testing.T) {
	temp := &params.ChainConfig{
		ClaudeBlock: big.NewInt(10000),
		ElwoodBlock: big.NewInt(10001),
	}
	assert.NoError(t, temp.CheckConfigForkOrder())

	assert.Equal(t, big.NewInt(0), GetCurrentEpoch(temp, big.NewInt(0)))
	assert.Equal(t, big.NewInt(1), GetCurrentEpoch(temp, big.NewInt(10000)))
	assert.Equal(t, big.NewInt(2), GetCurrentEpoch(temp, big.NewInt(10001)))
	assert.Equal(t, big.NewInt(3), GetCurrentEpoch(temp, new(big.Int).Add(big.NewInt(10001), EpochPeriod)))
	assert.Equal(t, big.NewInt(102), GetCurrentEpoch(temp, new(big.Int).Add(big.NewInt(10001), new(big.Int).Mul(big.NewInt(100), EpochPeriod))))
}
