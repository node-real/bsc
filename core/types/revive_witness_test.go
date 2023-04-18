package types

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
)

func makeSimpleReviveWitness(witType byte, data []byte) ReviveWitness {
	return ReviveWitness{
		WitnessType: witType,
		Data:        data,
	}
}

func makeReviveWitnessFromStorageTrieWitness(wit StorageTrieWitness) ReviveWitness {
	enc, err := rlp.EncodeToBytes(wit)
	if err != nil {
		panic(err)
	}
	return ReviveWitness{
		WitnessType: StorageTrieWitnessType,
		Data:        enc,
	}
}

func makeStorageTrieWitness(addr common.Address, proofCount int, proofLen ...int) StorageTrieWitness {
	proofList := make([]MPTProof, proofCount)
	for i := 0; i < proofCount; i++ {
		proof := make([][]byte, len(proofLen))
		for j := range proofLen {
			proof[j] = bytes.Repeat([]byte{'f'}, proofLen[j])
		}
		proofList[i] = MPTProof{
			RootKeyHex: nil,
			Proof:      proof,
		}
	}
	wit := StorageTrieWitness{
		Address:   addr,
		ProofList: proofList,
	}

	return wit
}

func TestVerifyWitness(t *testing.T) {
	addr := common.HexToAddress("0x0000000000000000000000000000000000000001")
	testData := []struct {
		wit    StorageTrieWitness
		expect error
	}{
		{
			wit:    makeStorageTrieWitness(addr, 0, 0),
			expect: ErrStorageTrieWitnessEmptyProofList,
		},
		{
			wit:    makeStorageTrieWitness(addr, 1, 31),
			expect: ErrStorageTrieWitnessWrongProofSize,
		},
		{
			wit:    makeStorageTrieWitness(addr, 1, 545),
			expect: ErrStorageTrieWitnessWrongProofSize,
		},
		{
			wit:    makeStorageTrieWitness(addr, 1, 32),
			expect: nil,
		},
		{
			wit:    makeStorageTrieWitness(addr, 1, 544),
			expect: nil,
		},
		{
			wit:    makeStorageTrieWitness(addr, 10, 32, 544, 33, 543, 128, 99),
			expect: nil,
		},
	}

	for i := range testData {
		assert.Equal(t, testData[i].expect, testData[i].wit.VerifyWitness(), i)
	}
}

func TestReviveWitness_VerifyWitness(t *testing.T) {

	addr := common.HexToAddress("0x0000000000000000000000000000000000000001")
	testData := []struct {
		wit    ReviveWitness
		expect error
	}{
		{
			wit:    makeReviveWitnessFromStorageTrieWitness(makeStorageTrieWitness(addr, 0, 0)),
			expect: ErrStorageTrieWitnessEmptyProofList,
		},
		{
			wit:    makeReviveWitnessFromStorageTrieWitness(makeStorageTrieWitness(addr, 1, 31)),
			expect: ErrStorageTrieWitnessWrongProofSize,
		},
		{
			wit:    makeSimpleReviveWitness(0, nil),
			expect: ErrWitnessEmptyData,
		},
		{
			wit:    makeSimpleReviveWitness(1, bytes.Repeat([]byte{'e'}, 10)),
			expect: ErrUnknownWitnessType,
		},
		{
			wit:    makeSimpleReviveWitness(0, bytes.Repeat([]byte{'e'}, 10)),
			expect: nil,
		},
		{
			wit:    makeReviveWitnessFromStorageTrieWitness(makeStorageTrieWitness(addr, 10, 33, 544, 99)),
			expect: nil,
		},
	}

	for i := range testData {
		if i == 4 {
			assert.Error(t, testData[i].wit.VerifyWitness())
			continue
		}
		assert.Equal(t, testData[i].expect, testData[i].wit.VerifyWitness(), i)
	}
}
