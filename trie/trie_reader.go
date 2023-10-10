// Copyright 2022 The go-ethereum Authors
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
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie/epochmeta"
	"github.com/ethereum/go-ethereum/trie/triestate"
	"math/big"
)

// Reader wraps the Node method of a backing trie store.
type Reader interface {
	// Node retrieves the trie node blob with the provided trie identifier, node path and
	// the corresponding node hash. No error will be returned if the node is not found.
	//
	// When looking up nodes in the account trie, 'owner' is the zero hash. For contract
	// storage trie nodes, 'owner' is the hash of the account address that containing the
	// storage.
	//
	// TODO(rjl493456442): remove the 'hash' parameter, it's redundant in PBSS.
	Node(owner common.Hash, path []byte, hash common.Hash) ([]byte, error)
}

// trieReader is a wrapper of the underlying node reader. It's not safe
// for concurrent usage.
type trieReader struct {
	owner  common.Hash
	reader Reader
	emdb   epochmeta.Storage
	banned map[string]struct{} // Marker to prevent node from being accessed, for tests
}

// newTrieReader initializes the trie reader with the given node reader.
func newTrieReader(stateRoot, owner common.Hash, db *Database) (*trieReader, error) {
	if stateRoot == (common.Hash{}) || stateRoot == types.EmptyRootHash {
		if stateRoot == (common.Hash{}) {
			log.Error("Zero state root hash!")
		}
		return &trieReader{owner: owner}, nil
	}
	reader, err := db.Reader(stateRoot)
	if err != nil {
		return nil, &MissingNodeError{Owner: owner, NodeHash: stateRoot, err: err}
	}
	tr := trieReader{owner: owner, reader: reader}
	if db.snapTree != nil {
		tr.emdb, err = epochmeta.NewEpochMetaDatabase(db.snapTree, new(big.Int), stateRoot)
		if err != nil {
			return nil, err
		}
	}
	return &tr, nil
}

// newEmptyReader initializes the pure in-memory reader. All read operations
// should be forbidden and returns the MissingNodeError.
func newEmptyReader() *trieReader {
	return &trieReader{}
}

// node retrieves the rlp-encoded trie node with the provided trie node
// information. An MissingNodeError will be returned in case the node is
// not found or any error is encountered.
func (r *trieReader) node(path []byte, hash common.Hash) ([]byte, error) {
	// Perform the logics in tests for preventing trie node access.
	if r.banned != nil {
		if _, ok := r.banned[string(path)]; ok {
			return nil, &MissingNodeError{Owner: r.owner, NodeHash: hash, Path: path}
		}
	}
	if r.reader == nil {
		return nil, &MissingNodeError{Owner: r.owner, NodeHash: hash, Path: path}
	}
	blob, err := r.reader.Node(r.owner, path, hash)
	if err != nil || len(blob) == 0 {
		return nil, &MissingNodeError{Owner: r.owner, NodeHash: hash, Path: path, err: err}
	}
	return blob, nil
}

// trieLoader implements triestate.TrieLoader for constructing tries.
type trieLoader struct {
	db *Database
}

// OpenTrie opens the main account trie.
func (l *trieLoader) OpenTrie(root common.Hash) (triestate.Trie, error) {
	return New(TrieID(root), l.db)
}

// OpenStorageTrie opens the storage trie of an account.
func (l *trieLoader) OpenStorageTrie(stateRoot common.Hash, addrHash, root common.Hash) (triestate.Trie, error) {
	return New(StorageTrieID(stateRoot, addrHash, root), l.db)
}

// epochMeta resolve from epoch meta storage
func (r *trieReader) epochMeta(path []byte) (*epochmeta.BranchNodeEpochMeta, error) {
	if r.emdb == nil {
		return nil, fmt.Errorf("cannot resolve epochmeta without db, path: %#x", path)
	}

	// epoch meta cloud be empty, because epoch0 or delete?
	blob, err := r.emdb.Get(r.owner, string(path))
	if err != nil {
		return nil, fmt.Errorf("resolve epoch meta err, path: %#x, err: %v", path, err)
	}
	if len(blob) == 0 {
		// set default epoch map
		// TODO(0xbundler): remove mem alloc?
		return epochmeta.NewBranchNodeEpochMeta([16]types.StateEpoch{}), nil
	}
	meta, err := epochmeta.DecodeFullNodeEpochMeta(blob)
	if err != nil {
		return nil, err
	}
	return meta, nil
}

// accountMeta resolve account metadata
func (r *trieReader) accountMeta() (types.MetaNoConsensus, error) {
	if r.emdb == nil {
		return types.EmptyMetaNoConsensus, errors.New("cannot resolve epoch meta without db for account")
	}

	blob, err := r.emdb.Get(r.owner, epochmeta.AccountMetadataPath)
	if err != nil {
		return types.EmptyMetaNoConsensus, fmt.Errorf("resolve epoch meta err for account, err: %v", err)
	}
	return types.DecodeMetaNoConsensusFromRLPBytes(blob)
}
