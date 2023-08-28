package ethdb

import (
	"context"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"strings"
	"time"
)

// FullStateDB expired state could fetch from it
type FullStateDB interface {
	// GetStorageReviveProof fetch target proof according to specific params
	GetStorageReviveProof(root common.Hash, account common.Address, prefixKeys, keys []string) ([]types.ReviveStorageProof, error)
}

type FullStateRPCServer struct {
	endpoint string
	client   *rpc.Client
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
	// TODO(0xbundler): add more opts, like auth?
	client, err := rpc.DialOptions(context.Background(), endpoint, nil)
	if err != nil {
		return nil, err
	}
	return &FullStateRPCServer{
		endpoint: endpoint,
		client:   client,
	}, nil
}

func (f *FullStateRPCServer) GetStorageReviveProof(root common.Hash, account common.Address, prefixKeys, keys []string) ([]types.ReviveStorageProof, error) {
	// TODO(0xbundler): add timeout in flags?
	ctx, cancelFunc := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelFunc()
	proofs := make([]types.ReviveStorageProof, 0, len(keys))
	err := f.client.CallContext(ctx, &proofs, "eth_getStorageReviveProof", account, prefixKeys, keys, root)
	if err != nil {
		return nil, err
	}
	return proofs, err
}
