// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package trie

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// ErrCommitted is returned when a already committed trie is requested for usage.
// The potential usages can be `Get`, `Update`, `Delete`, `NodeIterator`, `Prove`
// and so on.
var ErrCommitted = errors.New("trie is already committed")

// MissingNodeError is returned by the trie functions (Get, Update, Delete)
// in the case where a trie node is not present in the local database. It contains
// information necessary for retrieving the missing node.
type MissingNodeError struct {
	Owner    common.Hash // owner of the trie if it's 2-layered trie
	NodeHash common.Hash // hash of the missing node
	Path     []byte      // hex-encoded path to the missing node
	err      error       // concrete error for missing trie node
}

// Unwrap returns the concrete error for missing trie node which
// allows us for further analysis outside.
func (err *MissingNodeError) Unwrap() error {
	return err.err
}

func (err *MissingNodeError) Error() string {
	if err.Owner == (common.Hash{}) {
		return fmt.Sprintf("missing trie node %x (path %x) %v", err.NodeHash, err.Path, err.err)
	}
	return fmt.Sprintf("missing trie node %x (owner %x) (path %x) %v", err.NodeHash, err.Owner, err.Path, err.err)
}

type ReviveNotExpiredError struct {
	Path  []byte // hex-encoded path to the expired node
	Epoch types.StateEpoch
}

func NewReviveNotExpiredErr(path []byte, epoch types.StateEpoch) error {
	return &ReviveNotExpiredError{
		Path:  path,
		Epoch: epoch,
	}
}

func (e *ReviveNotExpiredError) Error() string {
	return fmt.Sprintf("revive not expired kv, path: %v, epoch: %v", e.Path, e.Epoch)
}

type ExpiredNodeError struct {
	Path  []byte // hex-encoded path to the expired node
	Epoch types.StateEpoch
	Node  node
}

func NewExpiredNodeError(path []byte, epoch types.StateEpoch, n node) error {
	return &ExpiredNodeError{
		Path:  path,
		Epoch: epoch,
		Node:  n,
	}
}

func (err *ExpiredNodeError) Error() string {
	return fmt.Sprintf("expired trie node, path: %v, epoch: %v, node: %v", err.Path, err.Epoch, err.Node.fstring(""))
}

func ParseExpiredNodeErr(err error) ([]byte, bool) {
	var path []byte
	switch enErr := err.(type) {
	case *ExpiredNodeError:
		path = enErr.Path
	case *MissingNodeError: // when meet MissingNodeError, try revive or fail
		path = enErr.Path
	default:
		return nil, false
	}

	return path, true
}
