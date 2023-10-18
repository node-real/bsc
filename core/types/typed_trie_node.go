package types

import (
	"bytes"
	"errors"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	TrieNodeRawType = iota
	TrieBranchNodeWithEpochType
)

var (
	ErrTypedNodeNotSupport = errors.New("the typed node not support now")
)

type TypedTrieNode interface {
	Type() uint8
	EncodeToRLPBytes(buf *rlp.EncoderBuffer)
}

type TrieNodeRaw []byte

func (n TrieNodeRaw) Type() uint8 {
	return TrieNodeRawType
}

func (n TrieNodeRaw) EncodeToRLPBytes(buf *rlp.EncoderBuffer) {
}

type TrieBranchNodeWithEpoch struct {
	EpochMap [16]StateEpoch
	Blob     []byte
}

func (n *TrieBranchNodeWithEpoch) Type() uint8 {
	return TrieBranchNodeWithEpochType
}

func (n *TrieBranchNodeWithEpoch) EncodeToRLPBytes(buf *rlp.EncoderBuffer) {
	rlp.Encode(buf, n)
}

func DecodeTrieBranchNodeWithEpoch(enc []byte) (*TrieBranchNodeWithEpoch, error) {
	var n TrieBranchNodeWithEpoch
	if err := rlp.DecodeBytes(enc, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

func EncodeTypedTrieNode(val TypedTrieNode) []byte {
	switch raw := val.(type) {
	case TrieNodeRaw:
		return raw
	}
	// encode with type prefix
	buf := bytes.NewBuffer(make([]byte, 0, 40))
	buf.WriteByte(val.Type())
	encoder := rlp.NewEncoderBuffer(buf)
	val.EncodeToRLPBytes(&encoder)
	// it cannot be error here.
	encoder.Flush()
	return buf.Bytes()
}

func DecodeTypedTrieNode(enc []byte) (TypedTrieNode, error) {
	if len(enc) == 0 {
		return TrieNodeRaw{}, nil
	}
	if len(enc) == 1 || enc[0] > 0x7f {
		return TrieNodeRaw(enc), nil
	}
	switch enc[0] {
	case TrieBranchNodeWithEpochType:
		return DecodeTrieBranchNodeWithEpoch(enc[1:])
	default:
		return nil, ErrTypedNodeNotSupport
	}
}

func DecodeTypedTrieNodeRaw(enc []byte) ([]byte, error) {
	if len(enc) == 0 {
		return enc, nil
	}
	if len(enc) == 1 || enc[0] > 0x7f {
		return enc, nil
	}
	switch enc[0] {
	case TrieBranchNodeWithEpochType:
		rn, err := DecodeTrieBranchNodeWithEpoch(enc[1:])
		if err != nil {
			return nil, err
		}
		return rn.Blob, nil
	default:
		return nil, ErrTypedNodeNotSupport
	}
}
