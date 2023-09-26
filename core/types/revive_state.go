package types

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type ReviveStorageProof struct {
	Key       string   `json:"key"`
	PrefixKey string   `json:"prefixKey"`
	Proof     []string `json:"proof"`
}

type ReviveResult struct {
	StorageProof []ReviveStorageProof `json:"storageProof"`
	BlockNum     hexutil.Uint64       `json:"blockNum"`
}
