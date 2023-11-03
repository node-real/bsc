package types

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetaEncodeDecode(t *testing.T) {
	tests := []struct {
		data MetaNoConsensus
	}{
		{data: EmptyMetaNoConsensus},
		{data: MetaNoConsensus(StateEpoch(10000))},
	}

	for _, item := range tests {
		enc, err := item.data.EncodeToRLPBytes()
		assert.NoError(t, err)
		t.Log(hex.EncodeToString(enc))
		mc, err := DecodeMetaNoConsensusFromRLPBytes(enc)
		assert.NoError(t, err)
		assert.Equal(t, item.data, mc)
	}
}
