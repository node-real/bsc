package state

import (
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/trie"
	"time"
)

var (
	reviveStorageTrieTimer = metrics.NewRegisteredTimer("state/revivetrie/rt", nil)
	EnableLocalRevive      = false // indicate if using local revive
)

// fetchExpiredStorageFromRemote request expired state from remote full state node;
func fetchExpiredStorageFromRemote(fullDB ethdb.FullStateDB, stateRoot common.Hash, addr common.Address, root common.Hash, tr Trie, prefixKey []byte, key common.Hash) (map[string][]byte, error) {
	log.Debug("fetching expired storage from remoteDB", "addr", addr, "prefix", prefixKey, "key", key)
	if EnableLocalRevive {
		// if there need revive expired state, try to revive locally, when the node is not being pruned, just renew the epoch
		val, err := tr.TryLocalRevive(addr, key.Bytes())
		log.Debug("fetchExpiredStorageFromRemote TryLocalRevive", "addr", addr, "key", key, "val", val, "err", err)
		if _, ok := err.(*trie.MissingNodeError); !ok {
			return nil, err
		}
		switch err.(type) {
		case *trie.MissingNodeError:
			// cannot revive locally, request from remote
		case nil:
			ret := make(map[string][]byte, 1)
			ret[key.String()] = val
			return ret, nil
		default:
			return nil, err
		}
	}

	// cannot revive locally, fetch remote proof
	proofs, err := fullDB.GetStorageReviveProof(stateRoot, addr, root, []string{common.Bytes2Hex(prefixKey)}, []string{common.Bytes2Hex(key[:])})
	log.Debug("fetchExpiredStorageFromRemote GetStorageReviveProof", "addr", addr, "key", key, "proofs", len(proofs), "err", err)
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
func reviveStorageTrie(addr common.Address, tr Trie, proof types.ReviveStorageProof, targetKey common.Hash) (map[string][]byte, error) {
	defer func(start time.Time) {
		reviveStorageTrieTimer.Update(time.Since(start))
	}(time.Now())

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

	nubs, err := tr.TryRevive(key, proofCache.CacheNubs())
	if err != nil {
		return nil, err
	}

	// check if it could get from trie
	if _, err = tr.GetStorage(addr, key); err != nil {
		return nil, err
	}

	ret := make(map[string][]byte)
	for _, nub := range nubs {
		kvs, err := nub.ResolveKV()
		if err != nil {
			return nil, err
		}
		for k, v := range kvs {
			ret[k] = v
		}
	}
	return ret, nil
}
