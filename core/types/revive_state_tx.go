package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

type WitnessList []ReviveWitness

// ReviveStateTx is the transaction for revive state.
type ReviveStateTx struct {
	Nonce       uint64          // nonce of sender account
	GasPrice    *big.Int        // wei per gas
	Gas         uint64          // gas limit
	To          *common.Address `rlp:"nil"` // nil means contract creation
	Value       *big.Int        // wei amount
	Data        []byte          // contract invocation input data
	WitnessList WitnessList     // revive witness

	V, R, S *big.Int // signature values
}

func (tx *ReviveStateTx) txType() byte {
	return ReviveStateTxType
}

func (tx *ReviveStateTx) copy() TxData {
	cpy := &ReviveStateTx{
		Nonce: tx.Nonce,
		To:    copyAddressPtr(tx.To),
		Data:  common.CopyBytes(tx.Data),
		Gas:   tx.Gas,
		// These are initialized below.
		Value:       new(big.Int),
		GasPrice:    new(big.Int),
		WitnessList: make(WitnessList, len(tx.WitnessList)),
		V:           new(big.Int),
		R:           new(big.Int),
		S:           new(big.Int),
	}

	for i := range tx.WitnessList {
		cpy.WitnessList[i] = tx.WitnessList[i].Copy()
	}
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.GasPrice != nil {
		cpy.GasPrice.Set(tx.GasPrice)
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}
	return cpy
}

func (tx *ReviveStateTx) chainID() *big.Int {
	return deriveChainId(tx.V)
}

func (tx *ReviveStateTx) accessList() AccessList {
	return nil
}

func (tx *ReviveStateTx) witnessList() WitnessList {
	return tx.WitnessList
}

func (tx *ReviveStateTx) data() []byte {
	return tx.Data
}

func (tx *ReviveStateTx) gas() uint64 {
	return tx.Gas
}

func (tx *ReviveStateTx) gasPrice() *big.Int {
	return tx.GasPrice
}

func (tx *ReviveStateTx) gasTipCap() *big.Int {
	return tx.GasPrice
}

func (tx *ReviveStateTx) gasFeeCap() *big.Int {
	return tx.GasPrice
}

func (tx *ReviveStateTx) value() *big.Int {
	return tx.Value
}

func (tx *ReviveStateTx) nonce() uint64 {
	return tx.Nonce
}

func (tx *ReviveStateTx) to() *common.Address {
	return tx.To
}

func (tx *ReviveStateTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *ReviveStateTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.V, tx.R, tx.S = v, r, s
}

func WitnessIntrinsicGas(wits WitnessList) (uint64, error) {
	totalGas := uint64(0)
	for i := 0; i < len(wits); i++ {
		totalGas += wits[i].Size() * params.TxWitnessListStorageGasPerByte
		addGas, err := wits[i].AdditionalIntrinsicGas()
		if err != nil {
			return 0, err
		}
		totalGas += addGas
	}
	return totalGas, nil
}
