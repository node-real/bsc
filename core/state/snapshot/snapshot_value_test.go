package snapshot

import (
	"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	val, _  = hex.DecodeString("0000f9eef0150e074b32e3b3b6d34d2534222292e3953019a41d714d135763a6")
	hash, _ = hex.DecodeString("2b6fad2e1335b0b4debd3de01c91f3f45d2b88465ff42ae2c53900f2f702101d")
)

func TestRawValueEncode(t *testing.T) {
	value := NewRawValue(val)
	enc1, _ := rlp.EncodeToBytes(value)
	buf := rlp.NewEncoderBuffer(nil)
	value.EncodeToRLPBytes(&buf)
	assert.Equal(t, enc1, buf.ToBytes())
}

func TestSnapValEncodeDecode(t *testing.T) {
	tests := []struct {
		raw SnapValue
	}{
		{
			raw: NewRawValue(val),
		},
		{
			raw: NewValueWithEpoch(types.StateEpoch(1000), common.BytesToHash(val)),
		},
		{
			raw: NewValueWithEpoch(types.StateEpoch(1000), common.Hash{}),
		},
	}
	for _, item := range tests {
		enc, err := EncodeValueToRLPBytes(item.raw)
		assert.NoError(t, err)
		t.Log(hex.EncodeToString(enc))
		tmp, err := DecodeValueFromRLPBytes(enc)
		assert.NoError(t, err)
		assert.Equal(t, item.raw, tmp)
	}
}
