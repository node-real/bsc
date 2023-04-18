package trie

import (
	"github.com/ethereum/go-ethereum/common"
)

//type shadowNode interface {
//	encode(encoder rlp.EncoderBuffer)
//}

type shadowExtensionNode struct {
	ShadowHash common.Hash
}

func NewShadowExtensionNode(hash common.Hash) shadowExtensionNode {
	return shadowExtensionNode{hash}
}

type shadowBranchNode struct {
	ShadowHash common.Hash
	EpochMap   [16]uint16
}

func NewShadowBranchNode(hash common.Hash, epochMap [16]uint16) shadowBranchNode {
	return shadowBranchNode{hash, epochMap}
}
