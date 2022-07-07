package core

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

// TODO: import from gatherer-verifier
type blockReceiptsRetrievalFn func(common.Hash) *types.Receipts
type diffLayerRetrievalFn func(common.Hash) *types.DiffLayer

func MakeGetBlockReceiptsFunc(bc *BlockChain) blockReceiptsRetrievalFn {
	return func(hash common.Hash) *types.Receipts {
		receipts := bc.GetReceiptsByHash(hash)
		return &receipts
	}
}

func MakeGetDiffLayerFunc(bc *blockChain) diffLayerRetrievalFn {
	return func(hash common.Hash) *types.DiffLayer {
		var bc *BlockChain
		data := bc.GetDiffLayerRLP(hash)
		var diffLayer types.DiffLayer
		if err := rlp.Decode(bytes.NewReader(data), diffLayer); err != nil {
			log.Error("Invalid block body RLP", "hash", hash, "err", err)
			return nil
		}
		return &diffLayer
	}
}
