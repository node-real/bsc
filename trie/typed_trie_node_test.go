package trie

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

var (
	fullNode1 = fullNode{
		EpochMap: randomEpochMap(),
		Children: [17]node{
			&shortNode{
				Key: common.FromHex("0x2e2"),
				Val: valueNode(common.FromHex("0x1")),
			},
			&shortNode{
				Key: common.FromHex("0x31f"),
				Val: valueNode(common.FromHex("0x2")),
			},
			hashNode(common.FromHex("0x1dce34c5cc509511f743349d758b8c38af8ac831432dbbfd989436acd3dbdeb8")),
			hashNode(common.FromHex("0x8bf421d69d8aacac46f15f0abd517e61e7ffe6b314a15a4fbce3e2a54323fa81")),
		},
	}
	fullNode2 = fullNode{
		EpochMap: randomEpochMap(),
		Children: [17]node{
			hashNode(common.FromHex("0xac51f786e6cee2f4575d19789c1e7ae91da54f2138f415c0f95f127c2893eff9")),
			hashNode(common.FromHex("0x83254958a3640af7a740dfcb32a02edfa1224e0ef65c28b1ff60c0b17eacb5d1")),
			hashNode(common.FromHex("0xc5f95b4bdbd1a17736a9162cd551d60c60252ea22d5016198ee6e5a5d04ac03a")),
			hashNode(common.FromHex("0xfe0654cc989b62dec1758daf6c4a29997f1f618d456981dd1d32f73c74c75151")),
		},
	}
	shortNode1 = shortNode{
		Key: common.FromHex("0xdf21"),
		Val: hashNode(common.FromHex("0x1dce34c5cc509511f743349d758b8c38af8ac831432dbbfd989436acd3dbdeb8")),
	}
	shortNode2 = shortNode{
		Key: common.FromHex("0xdf21"),
		Val: valueNode(common.FromHex("0x1af23")),
	}
)

func TestSimpleTypedNode_Encode_Decode(t *testing.T) {
	tests := []struct {
		n   types.TypedTrieNode
		err bool
	}{
		{
			n: types.TrieNodeRaw{},
		},
		{
			n:   types.TrieNodeRaw(common.FromHex("0x2465176C461AfB316ebc773C61fAEe85A6515DAA")),
			err: true,
		},
		{
			n: types.TrieNodeRaw(nodeToBytes(&shortNode1)),
		},
		{
			n: types.TrieNodeRaw(nodeToBytes(&shortNode2)),
		},
		{
			n: types.TrieNodeRaw(nodeToBytes(&fullNode1)),
		},
		{
			n: types.TrieNodeRaw(nodeToBytes(&fullNode2)),
		},
		{
			n: &types.TrieBranchNodeWithEpoch{
				EpochMap: fullNode1.EpochMap,
				Blob:     nodeToBytes(&fullNode1),
			},
		},
		{
			n: &types.TrieBranchNodeWithEpoch{
				EpochMap: fullNode2.EpochMap,
				Blob:     nodeToBytes(&fullNode2),
			},
		},
		{
			n: &types.TrieBranchNodeWithEpoch{
				EpochMap: randomEpochMap(),
				Blob:     nodeToBytes(&shortNode1),
			},
		},
		{
			n: &types.TrieBranchNodeWithEpoch{
				EpochMap: randomEpochMap(),
				Blob:     nodeToBytes(&shortNode2),
			},
		},
	}

	for i, item := range tests {
		enc := types.EncodeTypedTrieNode(item.n)
		t.Log(common.Bytes2Hex(enc))
		rn, err := types.DecodeTypedTrieNode(enc)
		if item.err {
			assert.Error(t, err, i)
			continue
		}
		assert.NoError(t, err, i)
		assert.Equal(t, item.n, rn, i)
	}
}

func TestNode2Bytes_Encode(t *testing.T) {
	tests := []struct {
		tn  types.TypedTrieNode
		n   node
		err bool
	}{
		{
			tn: &types.TrieBranchNodeWithEpoch{
				EpochMap: fullNode1.EpochMap,
				Blob:     nodeToBytes(&fullNode1),
			},
			n: &fullNode1,
		},
		{
			tn: &types.TrieBranchNodeWithEpoch{
				EpochMap: fullNode2.EpochMap,
				Blob:     nodeToBytes(&fullNode2),
			},
			n: &fullNode2,
		},
	}

	for i, item := range tests {
		enc1 := nodeToBytesWithEpoch(item.n)
		enc2 := types.EncodeTypedTrieNode(item.tn)
		t.Log(common.Bytes2Hex(enc1), common.Bytes2Hex(enc2))
		assert.Equal(t, enc2, enc1, i)
	}
}

func randomEpochMap() [16]types.StateEpoch {
	var ret [16]types.StateEpoch
	for i := range ret {
		ret[i] = types.StateEpoch(rand.Int() % 10000)
	}
	return ret
}
