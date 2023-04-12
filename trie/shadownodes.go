package trie

import (
	"github.com/ethereum/go-ethereum/common"
)

//type shadowNode interface {
//	encode(encoder rlp.EncoderBuffer)
//}

type shadowExtensionNode struct {
	ShadowHash *common.Hash
}

type shadowBranchNode struct {
	ShadowHash *common.Hash
	EpochMap   [16]uint16
}
