package ethdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/rpc"
	lru "github.com/hashicorp/golang-lru"
)

var (
	getProofMeter         = metrics.NewRegisteredMeter("ethdb/fullstatedb/getproof", nil)
	getProofHitCacheMeter = metrics.NewRegisteredMeter("ethdb/fullstatedb/getproof/cache", nil)
	getStorageProofTimer  = metrics.NewRegisteredTimer("ethdb/fullstatedb/getproof/rt", nil)
)

// FullStateDB expired state could fetch from it
type FullStateDB interface {
	// GetStorageReviveProof fetch target proof according to specific params
	GetStorageReviveProof(stateRoot common.Hash, account common.Address, root common.Hash, prefixKeys, keys []string) ([]types.ReviveStorageProof, error)
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

func (f *FullStateRPCServer) GetStorageReviveProof(stateRoot common.Hash, account common.Address, root common.Hash, prefixKeys, keys []string) ([]types.ReviveStorageProof, error) {
	defer func(start time.Time) {
		getStorageProofTimer.Update(time.Since(start))
	}(time.Now())

	var result types.ReviveResult

	getProofMeter.Mark(int64(len(keys)))
	// find from lru cache, now it cache key proof
	uncachedPrefixKeys := make([]string, 0, len(prefixKeys))
	uncachedKeys := make([]string, 0, len(keys))
	ret := make([]types.ReviveStorageProof, 0, len(keys))
	for i, key := range keys {
		val, ok := f.cache.Get(ProofCacheKey(account, root, prefixKeys[i], key))
		if !ok {
			uncachedPrefixKeys = append(uncachedPrefixKeys, prefixKeys[i])
			uncachedKeys = append(uncachedKeys, keys[i])
			continue
		}
		getProofHitCacheMeter.Mark(1)
		ret = append(ret, val.(types.ReviveStorageProof))
	}
	if len(uncachedKeys) == 0 {
		return ret, nil
	}

	// TODO(0xbundler): add timeout in flags?
	ctx, cancelFunc := context.WithTimeout(context.Background(), 1000*time.Millisecond)
	defer cancelFunc()
	err := f.client.CallContext(ctx, &result, "eth_getStorageReviveProof", stateRoot, account, root, uncachedKeys, uncachedPrefixKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to get storage revive proof, err: %v, remote's block number: %v", err, result.BlockNum)
	}
	if len(result.Err) > 0 {
		return nil, fmt.Errorf("failed to get storage revive proof, err: %v, remote's block number: %v", result.Err, result.BlockNum)
	}

	// add to cache
	for _, proof := range result.StorageProof {
		f.cache.Add(ProofCacheKey(account, root, proof.PrefixKey, proof.Key), proof)
	}

	ret = append(ret, result.StorageProof...)
	return ret, err
}

func ProofCacheKey(account common.Address, root common.Hash, prefix, key string) string {
	buf := bytes.NewBuffer(make([]byte, 0, 67+len(prefix)+len(key)))
	buf.Write(account[:])
	buf.WriteByte('$')
	buf.Write(root[:])
	buf.WriteByte('$')
	buf.WriteString(common.No0xPrefix(prefix))
	buf.WriteByte('$')
	buf.WriteString(common.No0xPrefix(key))
	return buf.String()
}

func ProofCacheTrie(blockRoot common.Hash, addr common.Address) string {
	buf := bytes.NewBuffer(make([]byte, 0, len(blockRoot)+len(addr)+1))
	buf.Write(blockRoot[:])
	buf.WriteByte('$')
	buf.Write(addr[:])
	return buf.String()
}
