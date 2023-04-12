package types

import (
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	ErrUnknownWitnessType                = errors.New("unknown revive witness type")
	ErrWitnessEmptyData                  = errors.New("witness data is empty")
	ErrStorageTrieWitnessEmptyProofList  = errors.New("StorageTrieWitness: empty proof list")
	ErrStorageTrieWitnessEmptyInnerProof = errors.New("StorageTrieWitness: empty inner proof")
	ErrStorageTrieWitnessWrongProofSize  = errors.New("StorageTrieWitness: wrong proof size")
)

const (
	StorageTrieWitnessType = iota
)

// MPTProof in order to degrade revive partial trie node,
// only allow on path proof, not support tree path,
// will verify the whole path later
// Attention: The proof could revive multi-vals, although it's a single trie path witness
type MPTProof struct {
	RootKeyHex []byte   // prefix key in nibbles format, max 65 bytes. TODO: optimize witness size
	Proof   [][]byte // list of RLP-encoded nodes
}

type StorageTrieWitness struct {
	Address   common.Address // target account address
	ProofList []MPTProof     // revive multiple slots (same address)
}

func (s *StorageTrieWitness) AdditionalIntrinsicGas() (uint64, error) {
	count := 0
	words := 0
	for i := range s.ProofList {
		for j := range s.ProofList[i].Proof {
			count++
			words += (len(s.ProofList[i].Proof[j]) + 31) / 32
		}
	}

	return uint64(count)*params.TxWitnessListVerifyMPTBaseGas + uint64(words)*params.TxWitnessListVerifyMPTGasPerWord, nil
}

// VerifyWitness only check format, merkle proof check later
func (s *StorageTrieWitness) VerifyWitness() error {
	if len(s.ProofList) == 0 {
		return ErrStorageTrieWitnessEmptyProofList
	}
	for i := range s.ProofList {
		if len(s.ProofList[i].Proof) == 0 {
			return ErrStorageTrieWitnessEmptyInnerProof
		}
		for j := range s.ProofList[i].Proof {
			// The smallest size is a valueNode, The largest size is the full fullNode
			if len(s.ProofList[i].Proof[j]) < 32 || len(s.ProofList[i].Proof[j]) > 544 {
				return ErrStorageTrieWitnessWrongProofSize
			}
		}
	}

	return nil
}

// ReviveWitnessData the common method of witness
type ReviveWitnessData interface {
	// AdditionalIntrinsicGas got additional gas consumption
	AdditionalIntrinsicGas() (uint64, error)
	// VerifyWitness check if valid witness format, used before state revival
	VerifyWitness() error
}

// ReviveWitness for revive witness
// Attention: it's not thread safe
type ReviveWitness struct {
	WitnessType byte              // only support Merkle Proof for now
	Data        []byte            // witness data, it's rlp format
	cache       ReviveWitnessData `rlp:"-" json:"-"` // cache if not encode to rlp or json, it used for performance
}

// Size estimate witness byte size
func (r *ReviveWitness) Size() uint64 {
	return uint64(len(r.Data) + 1)
}

// Copy deep copy
func (r *ReviveWitness) Copy() ReviveWitness {
	witness := ReviveWitness{
		WitnessType: r.WitnessType,
		Data:        make([]byte, len(r.Data)),
	}
	copy(witness.Data, r.Data)
	return witness
}

func (r *ReviveWitness) WitnessData() (ReviveWitnessData, error) {
	if r.cache == nil {
		if err := r.parseWitness(); err != nil {
			return nil, err
		}
	}
	return r.cache, nil
}

func (r *ReviveWitness) AdditionalIntrinsicGas() (uint64, error) {
	if r.cache == nil {
		if err := r.parseWitness(); err != nil {
			return 0, err
		}
	}
	return r.cache.AdditionalIntrinsicGas()
}

func (r *ReviveWitness) VerifyWitness() error {
	if r.cache == nil {
		if err := r.parseWitness(); err != nil {
			return err
		}
	}
	return r.cache.VerifyWitness()
}

func (r *ReviveWitness) parseWitness() error {
	if len(r.Data) == 0 {
		return ErrWitnessEmptyData
	}
	switch r.WitnessType {
	case StorageTrieWitnessType:
		var cache StorageTrieWitness
		if err := rlp.DecodeBytes(r.Data, &cache); err != nil {
			return err
		}
		r.cache = &cache
	default:
		return ErrUnknownWitnessType
	}

	return nil
}
