package types

import (
	"github.com/ethereum/go-ethereum/common"
)

type StateMeta interface {
	GetVersionNumber() uint8
	Hash() common.Hash
}

type MetaNoConsensus struct {
	Version uint8
	Epoch   uint16
}

func (m *MetaNoConsensus) GetVersionNumber() uint8 {
	return m.Version
}

func (m *MetaNoConsensus) Hash() common.Hash {
	return rlpHash(m.Epoch)
}
