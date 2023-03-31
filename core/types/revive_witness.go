package types

import "github.com/ethereum/go-ethereum/common"

const (
	MPTWitnessType = iota
)

type MPTProof struct {
	Key   []byte   // prefix key
	Proof [][]byte // list of RLP-encoded nodes
}

type ReviveWitness struct {
	WitnessType byte            // only support Merkle Proof for now
	Address     *common.Address // target account address
	ProofList   []MPTProof      // revive multiple slots (same address)
}

// Size estimate witness byte size
func (r *ReviveWitness) Size() uint64 {
	size := uint64(21)
	for i := range r.ProofList {
		size += uint64(len(r.ProofList[i].Key))
		for j := range r.ProofList[i].Proof {
			size += uint64(len(r.ProofList[i].Proof[j]))
		}
	}

	return size
}

// ProofWords get proof count and words
func (r *ReviveWitness) ProofWords() (uint64, uint64) {
	count := uint64(0)
	words := uint64(0)
	for i := range r.ProofList {
		for j := range r.ProofList[i].Proof {
			count++
			words += uint64((len(r.ProofList[i].Proof[j]) + 31) / 32)
		}
	}

	return count, words
}
