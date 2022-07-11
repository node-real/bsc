package core

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	gv "github.com/node-real/gatherer-verifier"
)

func MakeGetDiffLayerFunc(bc *BlockChain) func(common.Hash) *types.DiffLayer {
	return func(hash common.Hash) *types.DiffLayer {
		data := bc.GetDiffLayerRLP(hash)
		var diffLayer types.DiffLayer
		if err := rlp.Decode(bytes.NewReader(data), diffLayer); err != nil {
			log.Error("Invalid block body RLP", "hash", hash, "err", err)
			return nil
		}
		diffLayer.Receipts = bc.GetReceiptsByHash(hash)
		return &diffLayer
	}
}

func EnableGathererVerifier(cfg *gv.Config) BlockChainOption {
	return func(chain *BlockChain) *BlockChain {
		gathererVerifier, err := gv.New(cfg, gv.NewVerifier(chain.InsertChain, MakeGetDiffLayerFunc(chain)))
		if err != nil {
			panic(err)
		}
		chain.gathererVerifier = gathererVerifier
		return chain
	}
}
