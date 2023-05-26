package state

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
)

// ExpiredStateError Access State error, must revert the execution
type ExpiredStateError struct {
	Addr   common.Address
	Key    common.Hash
	Path   []byte
	Epoch  types.StateEpoch
	reason string
}

func NewSnapExpiredStateError(addr common.Address, key common.Hash, epoch types.StateEpoch) *ExpiredStateError {
	return &ExpiredStateError{
		Addr:   addr,
		Key:    key,
		Path:   []byte{},
		Epoch:  epoch,
		reason: "snap query",
	}
}

func NewExpiredStateError(addr common.Address, key common.Hash, err *trie.ExpiredNodeError) *ExpiredStateError {
	return &ExpiredStateError{
		Addr:   addr,
		Key:    key,
		Path:   err.Path,
		Epoch:  err.Epoch,
		reason: "query",
	}
}

func NewInsertExpiredStateError(addr common.Address, key common.Hash, err *trie.ExpiredNodeError) *ExpiredStateError {
	return &ExpiredStateError{
		Addr:   addr,
		Key:    key,
		Path:   err.Path,
		Epoch:  err.Epoch,
		reason: "insert",
	}
}

func (e *ExpiredStateError) Error() string {
	return fmt.Sprintf("Access expired state, addr: %v, path: %v, key: %v, epoch: %v, reason: %v", e.Addr, e.Path, e.Key, e.Epoch, e.reason)
}

func (e *ExpiredStateError) Reason(r string) *ExpiredStateError {
	e.reason = r
	return e
}
