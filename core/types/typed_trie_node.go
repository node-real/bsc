package types

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/rlp"
	"io"
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
	offset := buf.List()
	mapOffset := buf.List()
	for _, item := range n.EpochMap {
		if item == 0 {
			buf.Write(rlp.EmptyString)
		} else {
			buf.WriteUint64(uint64(item))
		}
	}
	buf.ListEnd(mapOffset)
	buf.Write(n.Blob)
	buf.ListEnd(offset)
}

func DecodeTrieBranchNodeWithEpoch(enc []byte) (*TrieBranchNodeWithEpoch, error) {
	var n TrieBranchNodeWithEpoch
	if len(enc) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	elems, _, err := rlp.SplitList(enc)
	if err != nil {
		return nil, fmt.Errorf("decode error: %v", err)
	}

	maps, rest, err := rlp.SplitList(elems)
	if err != nil {
		return nil, fmt.Errorf("decode epochmap error: %v", err)
	}
	for i := 0; i < len(n.EpochMap); i++ {
		var c uint64
		c, maps, err = rlp.SplitUint64(maps)
		if err != nil {
			return nil, fmt.Errorf("decode epochmap val error: %v", err)
		}
		n.EpochMap[i] = StateEpoch(c)
	}

	k, content, _, err := rlp.Split(rest)
	if err != nil {
		return nil, fmt.Errorf("decode raw error: %v", err)
	}
	switch k {
	case rlp.String:
		n.Blob = content
	case rlp.List:
		n.Blob = rest
	default:
		return nil, fmt.Errorf("decode wrong raw type error: %v", err)
	}
	return &n, nil
}

func EncodeTypedTrieNode(val TypedTrieNode) []byte {
	switch raw := val.(type) {
	case TrieNodeRaw:
		return raw
	case *TrieBranchNodeWithEpoch:
		// encode with type prefix
		w := rlp.NewEncoderBuffer(nil)
		w.Write([]byte{val.Type()})
		val.EncodeToRLPBytes(&w)
		result := w.ToBytes()
		w.Flush()
		return result
	}
	return nil
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
