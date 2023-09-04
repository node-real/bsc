package state

import (
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie"
)

// fetchExpiredStorageFromRemote request expired state from remote full state node;
func fetchExpiredStorageFromRemote(fullDB ethdb.FullStateDB, blockHash common.Hash, addr common.Address, tr Trie, prefixKey []byte, key common.Hash) ([]byte, error) {
	// if no prefix, query from revive trie, got the newest expired info
	if len(prefixKey) == 0 {
		_, err := tr.GetStorage(addr, key.Bytes())
		if enErr, ok := err.(*trie.ExpiredNodeError); ok {
			prefixKey = enErr.Path
		}
	}
	proofs, err := fullDB.GetStorageReviveProof(blockHash, addr, []string{common.Bytes2Hex(prefixKey)}, []string{common.Bytes2Hex(key[:])})
	if err != nil {
		return nil, err
	}

	if len(proofs) == 0 {
		log.Error("cannot find any revive proof from remoteDB", "addr", addr, "prefix", prefixKey, "key", key)
		return nil, fmt.Errorf("cannot find any revive proof from remoteDB")
	}

	return reviveStorageTrie(addr, tr, proofs[0], key)
}

// reviveStorageTrie revive trie's expired state from proof
func reviveStorageTrie(addr common.Address, tr Trie, proof types.ReviveStorageProof, targetKey common.Hash) ([]byte, error) {

	// Decode keys and proofs
	key := common.FromHex(proof.Key)
	if !bytes.Equal(targetKey[:], key) {
		return nil, fmt.Errorf("revive with wrong key, target: %#x, actual: %#x", targetKey, key)
	}
	prefixKey := common.FromHex(proof.PrefixKey)
	innerProofs := make([][]byte, 0, len(proof.Proof))
	for _, p := range proof.Proof {
		innerProofs = append(innerProofs, common.FromHex(p))
	}

	proofCache := trie.MPTProofCache{
		MPTProof: trie.MPTProof{
			RootKeyHex: prefixKey,
			Proof:      innerProofs,
		},
	}

	if err := proofCache.VerifyProof(); err != nil {
		return nil, err
	}

	nubs := tr.ReviveTrie(key, proofCache.CacheNubs())
	for _, nub := range nubs {
		val := nub.GetValue()
		if val != nil {
			return val, nil
		}
	}
	return nil, nil
}
