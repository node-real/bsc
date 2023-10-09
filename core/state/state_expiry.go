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
)

// stateExpiryMeta it contains all state expiry meta for target block
type stateExpiryMeta struct {
	enableStateExpiry bool
	enableLocalRevive bool
	fullStateDB       ethdb.FullStateDB
	epoch             types.StateEpoch
	originalRoot      common.Hash
	originalHash      common.Hash
}

func defaultStateExpiryMeta() *stateExpiryMeta {
	return &stateExpiryMeta{enableStateExpiry: false}
}

// fetchExpiredStorageFromRemote request expired state from remote full state node;
func fetchExpiredStorageFromRemote(meta *stateExpiryMeta, addr common.Address, root common.Hash, tr Trie, prefixKey []byte, key common.Hash) (map[string][]byte, error) {
	log.Debug("fetching expired storage from remoteDB", "addr", addr, "prefix", prefixKey, "key", key)
	if meta.enableLocalRevive {
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
	proofs, err := meta.fullStateDB.GetStorageReviveProof(meta.originalRoot, addr, root, []string{common.Bytes2Hex(prefixKey)}, []string{common.Bytes2Hex(key[:])})
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

// batchFetchExpiredStorageFromRemote request expired state from remote full state node with a list of keys and prefixes.
func batchFetchExpiredFromRemote(expiryMeta *stateExpiryMeta, addr common.Address, root common.Hash, tr Trie, prefixKeys [][]byte, keys []common.Hash) ([]map[string][]byte, error) {

	ret := make([]map[string][]byte, len(keys))
	prefixKeysStr := make([]string, len(prefixKeys))
	keysStr := make([]string, len(keys))

	if expiryMeta.enableLocalRevive {
		var expiredKeys []common.Hash
		var expiredPrefixKeys [][]byte
		for i, key := range keys {
			val, err := tr.TryLocalRevive(addr, key.Bytes())
			log.Debug("fetchExpiredStorageFromRemote TryLocalRevive", "addr", addr, "key", key, "val", val, "err", err)
			if _, ok := err.(*trie.MissingNodeError); !ok {
				return nil, err
			}
			switch err.(type) {
			case *trie.MissingNodeError:
				expiredKeys = append(expiredKeys, key)
				expiredPrefixKeys = append(expiredPrefixKeys, prefixKeys[i])
			case nil:
				kv := make(map[string][]byte, 1)
				kv[key.String()] = val
				ret = append(ret, kv)
			default:
				return nil, err
			}
		}

		for i, prefix := range expiredPrefixKeys {
			prefixKeysStr[i] = common.Bytes2Hex(prefix)
		}
		for i, key := range expiredKeys {
			keysStr[i] = common.Bytes2Hex(key[:])
		}

	} else {
		for i, prefix := range prefixKeys {
			prefixKeysStr[i] = common.Bytes2Hex(prefix)
		}

		for i, key := range keys {
			keysStr[i] = common.Bytes2Hex(key[:])
		}
	}

	// cannot revive locally, fetch remote proof
	proofs, err := expiryMeta.fullStateDB.GetStorageReviveProof(expiryMeta.originalRoot, addr, root, prefixKeysStr, keysStr)
	log.Debug("fetchExpiredStorageFromRemote GetStorageReviveProof", "addr", addr, "keys", keysStr, "prefixKeys", prefixKeysStr, "proofs", len(proofs), "err", err)
	if err != nil {
		return nil, err
	}

	if len(proofs) == 0 {
		log.Error("cannot find any revive proof from remoteDB", "addr", addr, "keys", keysStr, "prefixKeys", prefixKeysStr)
		return nil, fmt.Errorf("cannot find any revive proof from remoteDB")
	}

	for i, proof := range proofs {
		// kvs, err := reviveStorageTrie(addr, tr, proof, common.HexToHash(keysStr[i]))  // TODO(asyukii): this logically should work but it doesn't because of some reason, will need to investigate
		kvs, err := reviveStorageTrie(addr, tr, proof, common.HexToHash(proof.Key))
		if err != nil {
			log.Error("reviveStorageTrie failed", "addr", addr, "key", keys[i], "err", err)
			continue
		}
		ret = append(ret, kvs)
	}

	return ret, nil
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
