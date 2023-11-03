package snapshot

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
)

var (
	val, _ = hex.DecodeString("0000f9eef0150e074b32e3b3b6d34d2534222292e3953019a41d714d135763a6")
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
			raw: NewRawValue(common.FromHex("0x3")),
		},
		{
			raw: NewRawValue(val),
		},
		{
			raw: NewValueWithEpoch(types.StateEpoch(0), common.FromHex("0x00")),
		},
		{
			raw: NewValueWithEpoch(types.StateEpoch(0), common.FromHex("0x3")),
		},
		{
			raw: NewValueWithEpoch(types.StateEpoch(1), common.FromHex("0x3")),
		},
		{
			raw: NewValueWithEpoch(types.StateEpoch(0), val),
		},
		{
			raw: NewValueWithEpoch(types.StateEpoch(1000), val),
		},
		{
			raw: NewValueWithEpoch(types.StateEpoch(1000), []byte{}),
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
