package core

import (
	"bytes"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func keybytesToHex(str []byte) []byte {
	l := len(str)*2 + 1
	var nibbles = make([]byte, l)
	for i, b := range str {
		nibbles[i*2] = b / 16
		nibbles[i*2+1] = b % 16
	}
	nibbles[l-1] = 16
	return nibbles
}

func makeMerkleProofWitness(addr *common.Address, keyLen, witSize, proofCount, proofLen int) types.ReviveWitness {
	proofList := make([]types.MPTProof, witSize)
	for i := range proofList {
		proof := make([][]byte, proofCount)
		for j := range proof {
			proof[j] = bytes.Repeat([]byte{'p'}, proofLen)
		}
		proofList[i] = types.MPTProof{
			RootKeyHex: keybytesToHex(bytes.Repeat([]byte{'k'}, keyLen)),
			Proof:   proof,
		}
	}
	wit := types.StorageTrieWitness{
		Address:   *addr,
		ProofList: proofList,
	}

	enc, err := rlp.EncodeToBytes(wit)
	if err != nil {
		panic(err)
	}
	return types.ReviveWitness{
		WitnessType: types.StorageTrieWitnessType,
		Data:        enc,
	}
}

func TestIntrinsicGas_WitnessList(t *testing.T) {
	address := common.HexToAddress("d4584b5f6229b7be90727b0fc8c6b91bb427821f")

	test_data := []struct {
		// input
		data               []byte
		accessList         types.AccessList
		witnessList        types.WitnessList
		isContractCreation bool
		isHomestead        bool
		isEIP2028          bool
		// expect
		gas uint64
	}{
		{
			data:       common.Hex2Bytes("1234567890"),
			accessList: nil,
			witnessList: []types.ReviveWitness{
				makeMerkleProofWitness(&address, 100, 0, 100, 512),
			},
			isContractCreation: true,
			isHomestead:        true,
			isEIP2028:          true,
			gas:                53464,
		},
		{
			data:       common.Hex2Bytes("1234567890"),
			accessList: nil,
			witnessList: []types.ReviveWitness{
				makeMerkleProofWitness(&address, 100, 1, 0, 512),
			},
			isContractCreation: true,
			isHomestead:        true,
			isEIP2028:          true,
			gas:                55176,
		},
		{
			data:       common.Hex2Bytes("1234567890"),
			accessList: nil,
			witnessList: []types.ReviveWitness{
				makeMerkleProofWitness(&address, 100, 1, 1, 0),
			},
			isContractCreation: true,
			isHomestead:        true,
			isEIP2028:          true,
			gas:                55252,
		},
		{
			data:       nil,
			accessList: nil,
			witnessList: []types.ReviveWitness{
				makeMerkleProofWitness(&address, 30, 2, 2, 32),
				makeMerkleProofWitness(&address, 20, 1, 1, 36),
			},
			isContractCreation: false,
			isHomestead:        true,
			isEIP2028:          true,
			gas:                26412,
		},
	}

	for _, item := range test_data {
		gas, err := IntrinsicGas(item.data, item.accessList, item.witnessList, item.isContractCreation, item.isHomestead, item.isEIP2028)
		assert.NoError(t, err)
		assert.Equal(t, item.gas, gas)
	}
}
