package snapshot

import (
	"bytes"
	"errors"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	RawValueType       = iota // simple value, cannot exceed 32 bytes
	ValueWithEpochType        // value add epoch meta
)

var (
	ErrSnapValueNotSupport = errors.New("the snapshot type not support now")
)

type SnapValue interface {
	GetType() byte
	GetEpoch() types.StateEpoch
	GetVal() []byte // may cannot provide val in some value types
	EncodeToRLPBytes(buf *rlp.EncoderBuffer)
}

type RawValue []byte

func NewRawValue(val []byte) SnapValue {
	value := RawValue(val)
	return &value
}

func (v *RawValue) GetType() byte {
	return RawValueType
}

func (v *RawValue) GetEpoch() types.StateEpoch {
	return types.StateEpoch0
}

func (v *RawValue) GetVal() []byte {
	return *v
}

func (v *RawValue) EncodeToRLPBytes(buf *rlp.EncoderBuffer) {
	buf.WriteBytes(*v)
}

type ValueWithEpoch struct {
	Epoch types.StateEpoch // kv's epoch meta
	Val   []byte           // if val is empty hash, just encode as empty string in RLP
}

func NewValueWithEpoch(epoch types.StateEpoch, val []byte) SnapValue {
	if epoch == types.StateEpoch0 {
		return NewRawValue(val)
	}
	return &ValueWithEpoch{
		Epoch: epoch,
		Val:   val,
	}
}

func (v *ValueWithEpoch) GetType() byte {
	return ValueWithEpochType
}

func (v *ValueWithEpoch) GetEpoch() types.StateEpoch {
	return v.Epoch
}

func (v *ValueWithEpoch) GetVal() []byte {
	return v.Val
}

func (v *ValueWithEpoch) EncodeToRLPBytes(buf *rlp.EncoderBuffer) {
	offset := buf.List()
	buf.WriteUint64(uint64(v.Epoch))
	if len(v.Val) == 0 {
		buf.Write(rlp.EmptyString)
	} else {
		buf.WriteBytes(v.Val)
	}
	buf.ListEnd(offset)
}

func EncodeValueToRLPBytes(val SnapValue) ([]byte, error) {
	switch raw := val.(type) {
	case *RawValue:
		return rlp.EncodeToBytes(raw)
	default:
		return encodeTypedVal(val)
	}
}

func DecodeValueFromRLPBytes(b []byte) (SnapValue, error) {
	if len(b) == 0 {
		return &RawValue{}, nil
	}
	if len(b) == 1 || b[0] > 0x7f {
		var data RawValue
		_, data, _, err := rlp.Split(b)
		if err != nil {
			return nil, err
		}
		return &data, nil
	}
	return decodeTypedVal(b)
}

func decodeTypedVal(b []byte) (SnapValue, error) {
	switch b[0] {
	case ValueWithEpochType:
		var data ValueWithEpoch
		if err := decodeValueWithEpoch(b[1:], &data); err != nil {
			return nil, err
		}
		return &data, nil
	default:
		return nil, ErrSnapValueNotSupport
	}
}

func decodeValueWithEpoch(data []byte, v *ValueWithEpoch) error {
	elems, _, err := rlp.SplitList(data)
	if err != nil {
		return err
	}

	epoch, left, err := rlp.SplitUint64(elems)
	if err != nil {
		return err
	}
	v.Epoch = types.StateEpoch(epoch)

	val, _, err := rlp.SplitString(left)
	if err != nil {
		return err
	}
	if len(val) == 0 {
		v.Val = []byte{}
	} else {
		v.Val = val
	}
	return nil
}

func encodeTypedVal(val SnapValue) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 40))
	buf.WriteByte(val.GetType())
	encoder := rlp.NewEncoderBuffer(buf)
	val.EncodeToRLPBytes(&encoder)
	if err := encoder.Flush(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
