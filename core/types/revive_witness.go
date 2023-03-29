package types

import "github.com/ethereum/go-ethereum/common"

type MPTProof struct {
	key   []byte   // prefix key
	proof [][]byte // list of RLP-encoded nodes
}

type ReviveWitness struct {
	witnessType byte            // only support Merkle Proof for now
	address     *common.Address // target account address
	proofList   []MPTProof      // revive multiple slots (same address)
}
