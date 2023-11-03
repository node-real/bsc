package state

import (
	"bytes"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/trie"
)

var (
	reviveTrieTimer       = metrics.NewRegisteredTimer("state/revivetrie/rt", nil)
	reviveTrieMeter       = metrics.NewRegisteredMeter("state/revivetrie", nil)
	reviveFromLocalMeter  = metrics.NewRegisteredMeter("state/revivetrie/local", nil)
	reviveFromRemoteMeter = metrics.NewRegisteredMeter("state/revivetrie/remote", nil)
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

// tryReviveState request expired state from remote full state node;
func tryReviveState(meta *stateExpiryMeta, addr common.Address, root common.Hash, tr Trie, prefixKey []byte, key common.Hash, force bool) (map[string][]byte, error) {
	if !meta.enableStateExpiry {
		return nil, nil
	}
	//log.Debug("fetching expired storage from remoteDB", "addr", addr, "prefix", prefixKey, "key", key)
	reviveTrieMeter.Mark(1)
	if meta.enableLocalRevive && !force {
		// if there need revive expired state, try to revive locally, when the node is not being pruned, just renew the epoch
		val, err := tr.TryLocalRevive(addr, key.Bytes())
		//log.Debug("tryReviveState TryLocalRevive", "addr", addr, "key", key, "val", val, "err", err)
		switch err.(type) {
		case *trie.MissingNodeError:
			// cannot revive locally, request from remote
		case nil:
			reviveFromLocalMeter.Mark(1)
			return map[string][]byte{key.String(): val}, nil
		default:
			return nil, err
		}
	}

	reviveFromRemoteMeter.Mark(1)
	// cannot revive locally, fetch remote proof
	proofs, err := meta.fullStateDB.GetStorageReviveProof(meta.originalRoot, addr, root, []string{common.Bytes2Hex(prefixKey)}, []string{common.Bytes2Hex(key[:])})
	//log.Debug("tryReviveState GetStorageReviveProof", "addr", addr, "key", key, "proofs", len(proofs), "err", err)
	if err != nil {
		return nil, err
	}

	if len(proofs) == 0 {
		log.Error("cannot find any revive proof from remoteDB", "addr", addr, "prefix", prefixKey, "key", key)
		return nil, fmt.Errorf("cannot find any revive proof from remoteDB")
	}

	return ReviveStorageTrie(addr, tr, proofs[0], key)
}

// batchFetchExpiredStorageFromRemote request expired state from remote full state node with a list of keys and prefixes.
func batchFetchExpiredFromRemote(expiryMeta *stateExpiryMeta, addr common.Address, root common.Hash, tr Trie, prefixKeys [][]byte, keys []common.Hash) ([]map[string][]byte, error) {
	reviveTrieMeter.Mark(int64(len(keys)))
	ret := make([]map[string][]byte, len(keys))
	prefixKeysStr := make([]string, len(prefixKeys))
	keysStr := make([]string, len(keys))

	if expiryMeta.enableLocalRevive {
		var expiredKeys []common.Hash
		var expiredPrefixKeys [][]byte
		for i, key := range keys {
			val, err := tr.TryLocalRevive(addr, key.Bytes())
			//log.Debug("tryReviveState TryLocalRevive", "addr", addr, "key", key, "val", val, "err", err)
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
		reviveFromLocalMeter.Mark(int64(len(keys) - len(expiredKeys)))
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
	if len(prefixKeysStr) == 0 {
		return ret, nil
	}

	// cannot revive locally, fetch remote proof
	reviveFromRemoteMeter.Mark(int64(len(keysStr)))
	proofs, err := expiryMeta.fullStateDB.GetStorageReviveProof(expiryMeta.originalRoot, addr, root, prefixKeysStr, keysStr)
	//log.Debug("tryReviveState GetStorageReviveProof", "addr", addr, "keys", keysStr, "prefixKeys", prefixKeysStr, "proofs", len(proofs), "err", err)
	if err != nil {
		return nil, err
	}

	if len(proofs) == 0 {
		log.Error("cannot find any revive proof from remoteDB", "addr", addr, "keys", keysStr, "prefixKeys", prefixKeysStr)
		return nil, fmt.Errorf("cannot find any revive proof from remoteDB")
	}

	for i, proof := range proofs {
		// kvs, err := ReviveStorageTrie(addr, tr, proof, common.HexToHash(keysStr[i]))  // TODO(asyukii): this logically should work but it doesn't because of some reason, will need to investigate
		kvs, err := ReviveStorageTrie(addr, tr, proof, common.HexToHash(proof.Key))
		if err != nil {
			log.Error("reviveStorageTrie failed", "addr", addr, "key", keys[i], "err", err)
			continue
		}
		ret = append(ret, kvs)
	}

	return ret, nil
}

// ReviveStorageTrie revive trie's expired state from proof
func ReviveStorageTrie(addr common.Address, tr Trie, proof types.ReviveStorageProof, targetKey common.Hash) (map[string][]byte, error) {
	defer func(start time.Time) {
		reviveTrieTimer.Update(time.Since(start))
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

	mptProof := trie.NewMPTProof(prefixKey, innerProofs)
	ret, err := tr.TryRevive(key, mptProof)
	if err != nil {
		return nil, err
	}

	// check if it could get from trie
	if _, err = tr.GetStorage(addr, key); err != nil {
		return nil, err
	}

	return ret, nil
}
