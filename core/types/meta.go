package types

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	MetaNoConsensusType = iota
)

var (
	ErrMetaNotSupport = errors.New("the meta type not support now")
)

type MetaNoConsensus StateEpoch // Represents the epoch number

type StateMeta interface {
	GetType() byte
	Hash() common.Hash
	EncodeToRLPBytes() ([]byte, error)
}

func NewMetaNoConsensus(epoch StateEpoch) StateMeta {
	return MetaNoConsensus(epoch)
}

func (m MetaNoConsensus) GetType() byte {
	return MetaNoConsensusType
}

func (m MetaNoConsensus) Hash() common.Hash {
	return common.Hash{}
}

func (m MetaNoConsensus) EncodeToRLPBytes() ([]byte, error) {
	enc, err := rlp.EncodeToBytes(m)
	if err != nil {
		return nil, err
	}
	return enc, nil
}
