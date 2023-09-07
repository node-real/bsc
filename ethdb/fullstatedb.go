package ethdb

import (
	"bytes"
	"context"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/rpc"
	lru "github.com/hashicorp/golang-lru"
	"strings"
	"time"
)

var (
	getProofMeter         = metrics.NewRegisteredMeter("ethdb/fullstatedb/getproof", nil)
	getProofHitCacheMeter = metrics.NewRegisteredMeter("ethdb/fullstatedb/getproof/cache", nil)
)

// FullStateDB expired state could fetch from it
type FullStateDB interface {
	// GetStorageReviveProof fetch target proof according to specific params
	GetStorageReviveProof(blockHash common.Hash, account common.Address, prefixKeys, keys []string) ([]types.ReviveStorageProof, error)
}

type FullStateRPCServer struct {
	endpoint string
	client   *rpc.Client
	cache    *lru.Cache
}

func NewFullStateRPCServer(endpoint string) (FullStateDB, error) {
	if endpoint == "" {
		return nil, errors.New("endpoint must be specified")
	}
	if strings.HasPrefix(endpoint, "rpc:") || strings.HasPrefix(endpoint, "ipc:") {
		// Backwards compatibility with geth < 1.5 which required
		// these prefixes.
		endpoint = endpoint[4:]
	}
	// TODO(0xbundler): add more opts, like auth, cache size?
	client, err := rpc.DialOptions(context.Background(), endpoint)
	if err != nil {
		return nil, err
	}

	cache, err := lru.New(10000)
	if err != nil {
		return nil, err
	}
	return &FullStateRPCServer{
		endpoint: endpoint,
		client:   client,
		cache:    cache,
	}, nil
}

func (f *FullStateRPCServer) GetStorageReviveProof(blockHash common.Hash, account common.Address, prefixKeys, keys []string) ([]types.ReviveStorageProof, error) {
	getProofMeter.Mark(1)
	// find from lru cache, now it cache key proof
	uncahcedPrefixKeys := make([]string, 0, len(prefixKeys))
	uncahcedKeys := make([]string, 0, len(keys))
	ret := make([]types.ReviveStorageProof, 0, len(keys))
	for i, key := range keys {
		val, ok := f.cache.Get(proofCacheKey(blockHash, account, prefixKeys[i], key))
		log.Debug("GetStorageReviveProof hit cache", "account", account, "key", key, "ok", ok)
		if !ok {
			uncahcedPrefixKeys = append(uncahcedPrefixKeys, prefixKeys[i])
			uncahcedKeys = append(uncahcedKeys, keys[i])
			continue
		}
		getProofHitCacheMeter.Mark(1)
		ret = append(ret, val.(types.ReviveStorageProof))
	}

	// TODO(0xbundler): add timeout in flags?
	ctx, cancelFunc := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelFunc()
	proofs := make([]types.ReviveStorageProof, 0, len(uncahcedKeys))
	err := f.client.CallContext(ctx, &proofs, "eth_getStorageReviveProof", account, uncahcedKeys, uncahcedPrefixKeys, blockHash)
	if err != nil {
		return nil, err
	}

	// add to cache
	for _, proof := range proofs {
		f.cache.Add(proofCacheKey(blockHash, account, proof.PrefixKey, proof.Key), proof)
	}

	ret = append(ret, proofs...)
	return ret, err
}

func proofCacheKey(blockHash common.Hash, account common.Address, prefix, key string) string {
	buf := bytes.NewBuffer(make([]byte, 0, 67+len(prefix)+len(key)))
	buf.Write(blockHash[:])
	buf.WriteByte('$')
	buf.Write(account[:])
	buf.WriteByte('$')
	buf.WriteString(common.No0xPrefix(prefix))
	buf.WriteByte('$')
	buf.WriteString(common.No0xPrefix(key))
	return buf.String()
}
