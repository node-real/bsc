// Copyright 2014 The go-ethereum Authors
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

// Package trie implements Merkle Patricia Tries.
package trie

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"sync/atomic"
)

var (
	reviveMeter           = metrics.NewRegisteredMeter("trie/revive", nil)
	reviveNotExpiredMeter = metrics.NewRegisteredMeter("trie/revive/noexpired", nil)
	reviveErrMeter        = metrics.NewRegisteredMeter("trie/revive/err", nil)
)

// Trie is a Merkle Patricia Trie. Use New to create a trie that sits on
// top of a database. Whenever trie performs a commit operation, the generated
// nodes will be gathered and returned in a set. Once the trie is committed,
// it's not usable anymore. Callers have to re-create the trie with new root
// based on the updated trie database.
//
// Trie is not safe for concurrent use.
type Trie struct {
	root  node
	owner common.Hash // Can be used to identify account vs storage trie

	// Flag whether the commit operation is already performed. If so the
	// trie is not usable(latest states is invisible).
	committed bool

	// Keep track of the number leaves which have been inserted since the last
	// hashing operation. This number will not directly map to the number of
	// actually unhashed nodes.
	unhashed int

	// reader is the handler trie can retrieve nodes from.
	reader *trieReader

	// tracer is the tool to track the trie changes.
	// It will be reset after each commit operation.
	tracer *tracer

	// fields for state expiry
	currentEpoch types.StateEpoch
	rootEpoch    types.StateEpoch
	enableExpiry bool
}

// newFlag returns the cache flag value for a newly created node.
func (t *Trie) newFlag() nodeFlag {
	return nodeFlag{dirty: true}
}

// Copy returns a copy of Trie.
func (t *Trie) Copy() *Trie {
	return &Trie{
		root:         t.root,
		owner:        t.owner,
		committed:    t.committed,
		unhashed:     t.unhashed,
		reader:       t.reader,
		tracer:       t.tracer.copy(),
		rootEpoch:    t.rootEpoch,
		currentEpoch: t.currentEpoch,
		enableExpiry: t.enableExpiry,
	}
}

// New creates the trie instance with provided trie id and the read-only
// database. The state specified by trie id must be available, otherwise
// an error will be returned. The trie root specified by trie id can be
// zero hash or the sha3 hash of an empty string, then trie is initially
// empty, otherwise, the root node must be present in database or returns
// a MissingNodeError if not.
func New(id *ID, db *Database) (*Trie, error) {
	reader, err := newTrieReader(id.StateRoot, id.Owner, db)
	if err != nil {
		return nil, err
	}
	trie := &Trie{
		owner:        id.Owner,
		reader:       reader,
		tracer:       newTracer(),
		enableExpiry: enableStateExpiry(id, db),
	}
	// resolve root epoch
	if trie.enableExpiry {
		meta, err := reader.accountMeta()
		if err != nil {
			return nil, err
		}
		trie.rootEpoch = meta.Epoch()
		if id.Root != (common.Hash{}) && id.Root != types.EmptyRootHash {
			trie.root = hashNode(id.Root[:])
		}
		return trie, nil
	}

	if id.Root != (common.Hash{}) && id.Root != types.EmptyRootHash {
		rootnode, err := trie.resolveAndTrack(id.Root[:], nil)
		if err != nil {
			return nil, err
		}
		trie.root = rootnode
	}

	return trie, nil
}

func enableStateExpiry(id *ID, db *Database) bool {
	if db.snapTree == nil {
		return false
	}
	if id.Owner == (common.Hash{}) {
		return false
	}
	return true
}

// NewEmpty is a shortcut to create empty tree. It's mostly used in tests.
func NewEmpty(db *Database) *Trie {
	tr, _ := New(TrieID(types.EmptyRootHash), db)
	if db.snapTree != nil {
		tr.enableExpiry = true
	}
	return tr
}

// MustNodeIterator is a wrapper of NodeIterator and will omit any encountered
// error but just print out an error message.
func (t *Trie) MustNodeIterator(start []byte) NodeIterator {
	it, err := t.NodeIterator(start)
	if err != nil {
		log.Error("Unhandled trie error in Trie.NodeIterator", "err", err)
	}
	return it
}

// NodeIterator returns an iterator that returns nodes of the trie. Iteration starts at
// the key after the given start key.
func (t *Trie) NodeIterator(start []byte) (NodeIterator, error) {
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return nil, ErrCommitted
	}
	return newNodeIterator(t, start), nil
}

// MustGet is a wrapper of Get and will omit any encountered error but just
// print out an error message.
func (t *Trie) MustGet(key []byte) []byte {
	res, err := t.Get(key)
	if err != nil {
		log.Error("Unhandled trie error in Trie.Get", "err", err)
	}
	return res
}

// Get returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
func (t *Trie) Get(key []byte) (value []byte, err error) {
	var newroot node
	var didResolve bool

	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return nil, ErrCommitted
	}

	if t.enableExpiry {
		value, newroot, didResolve, err = t.getWithEpoch(t.root, keybytesToHex(key), 0, t.getRootEpoch(), false)
	} else {
		value, newroot, didResolve, err = t.get(t.root, keybytesToHex(key), 0)
	}
	if err == nil && didResolve {
		t.root = newroot
	}
	return value, err
}

func (t *Trie) GetAndUpdateEpoch(key []byte) (value []byte, err error) {
	if !t.enableExpiry {
		return nil, errors.New("expiry is not enabled")
	}

	value, newroot, didResolve, err := t.getWithEpoch(t.root, keybytesToHex(key), 0, t.getRootEpoch(), true)

	if err == nil && didResolve {
		t.root = newroot
		t.rootEpoch = t.currentEpoch
	}
	return value, err
}

func (t *Trie) get(origNode node, key []byte, pos int) (value []byte, newnode node, didResolve bool, err error) {
	switch n := (origNode).(type) {
	case nil:
		return nil, nil, false, nil
	case valueNode:
		return n, n, false, nil
	case *shortNode:
		if len(key)-pos < len(n.Key) || !bytes.Equal(n.Key, key[pos:pos+len(n.Key)]) {
			// key not found in trie
			return nil, n, false, nil
		}
		value, newnode, didResolve, err = t.get(n.Val, key, pos+len(n.Key))
		if err == nil && didResolve {
			n = n.copy()
			n.Val = newnode
		}
		return value, n, didResolve, err
	case *fullNode:
		value, newnode, didResolve, err = t.get(n.Children[key[pos]], key, pos+1)
		if err == nil && didResolve {
			n = n.copy()
			n.Children[key[pos]] = newnode
		}
		return value, n, didResolve, err
	case hashNode:
		child, err := t.resolveAndTrack(n, key[:pos])
		if err != nil {
			return nil, n, true, err
		}
		value, newnode, _, err := t.get(child, key, pos)
		return value, newnode, true, err
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}

func (t *Trie) getWithEpoch(origNode node, key []byte, pos int, epoch types.StateEpoch, updateEpoch bool) (value []byte, newnode node, didResolve bool, err error) {
	if t.epochExpired(origNode, epoch) {
		return nil, nil, false, NewExpiredNodeError(key[:pos], epoch)
	}
	switch n := (origNode).(type) {
	case nil:
		return nil, nil, false, nil
	case valueNode:
		return n, n, false, nil
	case *shortNode:
		if len(key)-pos < len(n.Key) || !bytes.Equal(n.Key, key[pos:pos+len(n.Key)]) {
			// key not found in trie
			return nil, n, false, nil
		}
		value, newnode, didResolve, err = t.getWithEpoch(n.Val, key, pos+len(n.Key), epoch, updateEpoch)
		if err == nil && t.renewNode(epoch, didResolve, updateEpoch) {
			n = n.copy()
			n.Val = newnode
			if updateEpoch {
				n.setEpoch(t.currentEpoch)
			}
			didResolve = true
		}
		return value, n, didResolve, err
	case *fullNode:
		value, newnode, didResolve, err = t.getWithEpoch(n.Children[key[pos]], key, pos+1, n.GetChildEpoch(int(key[pos])), updateEpoch)
		if err == nil && t.renewNode(epoch, didResolve, updateEpoch) {
			n = n.copy()
			n.Children[key[pos]] = newnode
			if updateEpoch {
				n.setEpoch(t.currentEpoch)
			}
			if updateEpoch && newnode != nil {
				n.UpdateChildEpoch(int(key[pos]), t.currentEpoch)
			}
			didResolve = true
		}
		return value, n, didResolve, err
	case hashNode:
		child, err := t.resolveAndTrack(n, key[:pos])
		if err != nil {
			return nil, n, true, err
		}

		if child, ok := child.(*fullNode); ok {
			if err = t.resolveEpochMeta(child, epoch, key[:pos]); err != nil {
				return nil, n, true, err
			}
		}
		value, newnode, _, err := t.getWithEpoch(child, key, pos, epoch, updateEpoch)
		return value, newnode, true, err
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}

// updateChildNodeEpoch traverses the trie and update the node epoch for each accessed trie node.
// Under an expiry scheme where a hash node is accessed, its parent node's epoch will not be updated.
func (t *Trie) updateChildNodeEpoch(origNode node, key []byte, pos int, epoch types.StateEpoch) (newnode node, updateEpoch bool, err error) {
	switch n := (origNode).(type) {
	case nil:
		return nil, false, nil
	case valueNode:
		return n, true, nil
	case *shortNode:
		if len(key)-pos < len(n.Key) || !bytes.Equal(n.Key, key[pos:pos+len(n.Key)]) {
			return n, false, nil
		}
		newnode, updateEpoch, err = t.updateChildNodeEpoch(n.Val, key, pos+len(n.Key), epoch)
		if err == nil && updateEpoch {
			n = n.copy()
			n.Val = newnode
			n.setEpoch(t.currentEpoch)
			n.flags = t.newFlag()
		}
		return n, true, err
	case *fullNode:
		newnode, updateEpoch, err = t.updateChildNodeEpoch(n.Children[key[pos]], key, pos+1, epoch)
		if err == nil && updateEpoch {
			n = n.copy()
			n.Children[key[pos]] = newnode
			n.setEpoch(t.currentEpoch)
			n.UpdateChildEpoch(int(key[pos]), t.currentEpoch)
			n.flags = t.newFlag()
		}
		return n, true, err
	case hashNode:
		return n, false, err
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}

// MustGetNode is a wrapper of GetNode and will omit any encountered error but
// just print out an error message.
func (t *Trie) MustGetNode(path []byte) ([]byte, int) {
	item, resolved, err := t.GetNode(path)
	if err != nil {
		log.Error("Unhandled trie error in Trie.GetNode", "err", err)
	}
	return item, resolved
}

// GetNode retrieves a trie node by compact-encoded path. It is not possible
// to use keybyte-encoding as the path might contain odd nibbles.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
func (t *Trie) GetNode(path []byte) ([]byte, int, error) {
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return nil, 0, ErrCommitted
	}
	item, newroot, resolved, err := t.getNode(t.root, compactToHex(path), 0)
	if err != nil {
		return nil, resolved, err
	}
	if resolved > 0 {
		t.root = newroot
	}
	if item == nil {
		return nil, resolved, nil
	}
	return item, resolved, nil
}

func (t *Trie) getNode(origNode node, path []byte, pos int) (item []byte, newnode node, resolved int, err error) {
	// If non-existent path requested, abort
	if origNode == nil {
		return nil, nil, 0, nil
	}
	// If we reached the requested path, return the current node
	if pos >= len(path) {
		// Although we most probably have the original node expanded, encoding
		// that into consensus form can be nasty (needs to cascade down) and
		// time consuming. Instead, just pull the hash up from disk directly.
		var hash hashNode
		if node, ok := origNode.(hashNode); ok {
			hash = node
		} else {
			hash, _ = origNode.cache()
		}
		if hash == nil {
			return nil, origNode, 0, errors.New("non-consensus node")
		}
		blob, err := t.reader.node(path, common.BytesToHash(hash))
		return blob, origNode, 1, err
	}
	// Path still needs to be traversed, descend into children
	switch n := (origNode).(type) {
	case valueNode:
		// Path prematurely ended, abort
		return nil, nil, 0, nil

	case *shortNode:
		if len(path)-pos < len(n.Key) || !bytes.Equal(n.Key, path[pos:pos+len(n.Key)]) {
			// Path branches off from short node
			return nil, n, 0, nil
		}
		item, newnode, resolved, err = t.getNode(n.Val, path, pos+len(n.Key))
		if err == nil && resolved > 0 {
			n = n.copy()
			n.Val = newnode
		}
		return item, n, resolved, err

	case *fullNode:
		item, newnode, resolved, err = t.getNode(n.Children[path[pos]], path, pos+1)
		if err == nil && resolved > 0 {
			n = n.copy()
			n.Children[path[pos]] = newnode
		}
		return item, n, resolved, err

	case hashNode:
		child, err := t.resolveAndTrack(n, path[:pos])
		if err != nil {
			return nil, n, 1, err
		}
		item, newnode, resolved, err := t.getNode(child, path, pos)
		return item, newnode, resolved + 1, err

	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}

// MustUpdate is a wrapper of Update and will omit any encountered error but
// just print out an error message.
func (t *Trie) MustUpdate(key, value []byte) {
	if err := t.Update(key, value); err != nil {
		log.Error("Unhandled trie error in Trie.Update", "err", err)
	}
}

// Update associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
func (t *Trie) Update(key, value []byte) error {
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return ErrCommitted
	}

	if t.enableExpiry {
		return t.updateWithEpoch(key, value, t.getRootEpoch())
	}
	return t.update(key, value)
}

func (t *Trie) update(key, value []byte) error {
	t.unhashed++
	k := keybytesToHex(key)
	if len(value) != 0 {
		_, n, err := t.insert(t.root, nil, k, valueNode(value))
		if err != nil {
			return err
		}
		t.root = n
	} else {
		_, n, err := t.delete(t.root, nil, k)
		if err != nil {
			return err
		}
		t.root = n
	}
	return nil
}

func (t *Trie) updateWithEpoch(key, value []byte, epoch types.StateEpoch) error {
	t.unhashed++
	k := keybytesToHex(key)
	if len(value) != 0 {
		_, n, err := t.insertWithEpoch(t.root, nil, k, valueNode(value), epoch)
		if err != nil {
			return err
		}
		t.root = n
	} else {
		_, n, err := t.deleteWithEpoch(t.root, nil, k, epoch)
		if err != nil {
			return err
		}
		t.root = n
	}
	t.rootEpoch = t.currentEpoch
	return nil
}

func (t *Trie) insert(n node, prefix, key []byte, value node) (bool, node, error) {
	if len(key) == 0 {
		if v, ok := n.(valueNode); ok {
			return !bytes.Equal(v, value.(valueNode)), value, nil
		}
		return true, value, nil
	}
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		// If the whole key matches, keep this short node as is
		// and only update the value.
		if matchlen == len(n.Key) {
			dirty, nn, err := t.insert(n.Val, append(prefix, key[:matchlen]...), key[matchlen:], value)
			if !dirty || err != nil {
				return false, n, err
			}
			return true, &shortNode{Key: n.Key, Val: nn, flags: t.newFlag()}, nil
		}
		// Otherwise branch out at the index where they differ.
		branch := &fullNode{flags: t.newFlag()}
		var err error
		_, branch.Children[n.Key[matchlen]], err = t.insert(nil, append(prefix, n.Key[:matchlen+1]...), n.Key[matchlen+1:], n.Val)
		if err != nil {
			return false, nil, err
		}
		_, branch.Children[key[matchlen]], err = t.insert(nil, append(prefix, key[:matchlen+1]...), key[matchlen+1:], value)
		if err != nil {
			return false, nil, err
		}
		// Replace this shortNode with the branch if it occurs at index 0.
		if matchlen == 0 {
			t.tracer.onExpandToBranchNode(prefix)
			return true, branch, nil
		}
		// New branch node is created as a child of the original short node.
		// Track the newly inserted node in the tracer. The node identifier
		// passed is the path from the root node.
		t.tracer.onInsert(append(prefix, key[:matchlen]...))
		t.tracer.onExpandToBranchNode(append(prefix, key[:matchlen]...))

		// Replace it with a short node leading up to the branch.
		return true, &shortNode{Key: key[:matchlen], Val: branch, flags: t.newFlag()}, nil

	case *fullNode:
		dirty, nn, err := t.insert(n.Children[key[0]], append(prefix, key[0]), key[1:], value)
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn
		return true, n, nil

	case nil:
		// New short node is created and track it in the tracer. The node identifier
		// passed is the path from the root node. Note the valueNode won't be tracked
		// since it's always embedded in its parent.
		t.tracer.onInsert(prefix)

		return true, &shortNode{Key: key, Val: value, flags: t.newFlag()}, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and insert into it. This leaves all child nodes on
		// the path to the value in the trie.
		rn, err := t.resolveAndTrack(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.insert(rn, prefix, key, value)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

func (t *Trie) insertWithEpoch(n node, prefix, key []byte, value node, epoch types.StateEpoch) (bool, node, error) {
	if t.epochExpired(n, epoch) {
		return false, nil, NewExpiredNodeError(prefix, epoch)
	}

	if len(key) == 0 {
		if v, ok := n.(valueNode); ok {
			return !bytes.Equal(v, value.(valueNode)), value, nil
		}
		return true, value, nil
	}
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		// If the whole key matches, keep this short node as is
		// and only update the value.
		if matchlen == len(n.Key) {
			dirty, nn, err := t.insertWithEpoch(n.Val, append(prefix, key[:matchlen]...), key[matchlen:], value, epoch)
			if !t.renewNode(epoch, dirty, true) || err != nil {
				return false, n, err
			}
			return true, &shortNode{Key: n.Key, Val: nn, flags: t.newFlag(), epoch: t.currentEpoch}, nil
		}
		// Otherwise branch out at the index where they differ.
		branch := &fullNode{flags: t.newFlag(), epoch: t.currentEpoch}
		var err error
		_, branch.Children[n.Key[matchlen]], err = t.insertWithEpoch(nil, append(prefix, n.Key[:matchlen+1]...), n.Key[matchlen+1:], n.Val, t.currentEpoch)
		if err != nil {
			return false, nil, err
		}
		branch.UpdateChildEpoch(int(n.Key[matchlen]), t.currentEpoch)

		_, branch.Children[key[matchlen]], err = t.insertWithEpoch(nil, append(prefix, key[:matchlen+1]...), key[matchlen+1:], value, t.currentEpoch)
		if err != nil {
			return false, nil, err
		}
		branch.UpdateChildEpoch(int(key[matchlen]), t.currentEpoch)
		branch.setEpoch(t.currentEpoch)

		// Replace this shortNode with the branch if it occurs at index 0.
		if matchlen == 0 {
			t.tracer.onExpandToBranchNode(prefix)
			return true, branch, nil
		}
		// New branch node is created as a child of the original short node.
		// Track the newly inserted node in the tracer. The node identifier
		// passed is the path from the root node.
		t.tracer.onInsert(append(prefix, key[:matchlen]...))
		t.tracer.onExpandToBranchNode(append(prefix, key[:matchlen]...))

		// Replace it with a short node leading up to the branch.
		return true, &shortNode{Key: key[:matchlen], Val: branch, flags: t.newFlag(), epoch: t.currentEpoch}, nil

	case *fullNode:
		dirty, nn, err := t.insertWithEpoch(n.Children[key[0]], append(prefix, key[0]), key[1:], value, n.GetChildEpoch(int(key[0])))
		if !t.renewNode(epoch, dirty, true) || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn
		n.setEpoch(t.currentEpoch)
		n.UpdateChildEpoch(int(key[0]), t.currentEpoch)

		return true, n, nil

	case nil:
		// New short node is created and track it in the tracer. The node identifier
		// passed is the path from the root node. Note the valueNode won't be tracked
		// since it's always embedded in its parent.
		t.tracer.onInsert(prefix)

		return true, &shortNode{Key: key, Val: value, flags: t.newFlag(), epoch: t.currentEpoch}, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and insert into it. This leaves all child nodes on
		// the path to the value in the trie.
		rn, err := t.resolveAndTrack(n, prefix)
		if err != nil {
			return false, nil, err
		}

		if child, ok := rn.(*fullNode); ok {
			if err = t.resolveEpochMeta(child, epoch, prefix); err != nil {
				return false, nil, err
			}
		}

		dirty, nn, err := t.insertWithEpoch(rn, prefix, key, value, epoch)
		if !t.renewNode(epoch, dirty, true) || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// MustDelete is a wrapper of Delete and will omit any encountered error but
// just print out an error message.
func (t *Trie) MustDelete(key []byte) {
	if err := t.Delete(key); err != nil {
		log.Error("Unhandled trie error in Trie.Delete", "err", err)
	}
}

// Delete removes any existing value for key from the trie.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
func (t *Trie) Delete(key []byte) error {
	var n node
	var err error
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return ErrCommitted
	}
	t.unhashed++
	k := keybytesToHex(key)

	if t.enableExpiry {
		_, n, err = t.deleteWithEpoch(t.root, nil, k, t.getRootEpoch())
		t.rootEpoch = t.currentEpoch
	} else {
		_, n, err = t.delete(t.root, nil, k)
	}

	if err != nil {
		return err
	}
	t.root = n
	return nil
}

// delete returns the new root of the trie with key deleted.
// It reduces the trie to minimal form by simplifying
// nodes on the way up after deleting recursively.
func (t *Trie) delete(n node, prefix, key []byte) (bool, node, error) {
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		if matchlen < len(n.Key) {
			return false, n, nil // don't replace n on mismatch
		}
		if matchlen == len(key) {
			// The matched short node is deleted entirely and track
			// it in the deletion set. The same the valueNode doesn't
			// need to be tracked at all since it's always embedded.
			t.tracer.onDelete(prefix)

			return true, nil, nil // remove n entirely for whole matches
		}
		// The key is longer than n.Key. Remove the remaining suffix
		// from the subtrie. Child can never be nil here since the
		// subtrie must contain at least two other values with keys
		// longer than n.Key.
		dirty, child, err := t.delete(n.Val, append(prefix, key[:len(n.Key)]...), key[len(n.Key):])
		if !dirty || err != nil {
			return false, n, err
		}
		switch child := child.(type) {
		case *shortNode:
			// The child shortNode is merged into its parent, track
			// is deleted as well.
			t.tracer.onDelete(append(prefix, n.Key...))

			// Deleting from the subtrie reduced it to another
			// short node. Merge the nodes to avoid creating a
			// shortNode{..., shortNode{...}}. Use concat (which
			// always creates a new slice) instead of append to
			// avoid modifying n.Key since it might be shared with
			// other nodes.
			return true, &shortNode{Key: concat(n.Key, child.Key...), Val: child.Val, flags: t.newFlag()}, nil
		default:
			return true, &shortNode{Key: n.Key, Val: child, flags: t.newFlag()}, nil
		}

	case *fullNode:
		dirty, nn, err := t.delete(n.Children[key[0]], append(prefix, key[0]), key[1:])
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn

		// Because n is a full node, it must've contained at least two children
		// before the delete operation. If the new child value is non-nil, n still
		// has at least two children after the deletion, and cannot be reduced to
		// a short node.
		if nn != nil {
			return true, n, nil
		}
		// Reduction:
		// Check how many non-nil entries are left after deleting and
		// reduce the full node to a short node if only one entry is
		// left. Since n must've contained at least two children
		// before deletion (otherwise it would not be a full node) n
		// can never be reduced to nil.
		//
		// When the loop is done, pos contains the index of the single
		// value that is left in n or -2 if n contains at least two
		// values.
		pos := -1
		for i, cld := range &n.Children {
			if cld != nil {
				if pos == -1 {
					pos = i
				} else {
					pos = -2
					break
				}
			}
		}
		if pos >= 0 {
			if pos != 16 {
				// If the remaining entry is a short node, it replaces
				// n and its key gets the missing nibble tacked to the
				// front. This avoids creating an invalid
				// shortNode{..., shortNode{...}}.  Since the entry
				// might not be loaded yet, resolve it just for this
				// check.
				cnode, err := t.resolve(n.Children[pos], append(prefix, byte(pos)))
				if err != nil {
					return false, nil, err
				}
				if cnode, ok := cnode.(*shortNode); ok {
					// Replace the entire full node with the short node.
					// Mark the original short node as deleted since the
					// value is embedded into the parent now.
					t.tracer.onDelete(append(prefix, byte(pos)))
					t.tracer.onDeleteBranchNode(prefix)

					k := append([]byte{byte(pos)}, cnode.Key...)
					return true, &shortNode{Key: k, Val: cnode.Val, flags: t.newFlag()}, nil
				}
			}
			// Otherwise, n is replaced by a one-nibble short node
			// containing the child.
			t.tracer.onDeleteBranchNode(prefix)
			return true, &shortNode{Key: []byte{byte(pos)}, Val: n.Children[pos], flags: t.newFlag()}, nil
		}
		// n still contains at least two values and cannot be reduced.
		return true, n, nil

	case valueNode:
		return true, nil, nil

	case nil:
		return false, nil, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and delete from it. This leaves all child nodes on
		// the path to the value in the trie.
		rn, err := t.resolveAndTrack(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.delete(rn, prefix, key)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v (%v)", n, n, key))
	}
}

func (t *Trie) deleteWithEpoch(n node, prefix, key []byte, epoch types.StateEpoch) (bool, node, error) {
	if t.epochExpired(n, epoch) {
		return false, nil, NewExpiredNodeError(prefix, epoch)
	}

	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		if matchlen < len(n.Key) {
			return false, n, nil // don't replace n on mismatch
		}
		if matchlen == len(key) {
			// The matched short node is deleted entirely and track
			// it in the deletion set. The same the valueNode doesn't
			// need to be tracked at all since it's always embedded.
			t.tracer.onDelete(prefix)

			return true, nil, nil // remove n entirely for whole matches
		}
		// The key is longer than n.Key. Remove the remaining suffix
		// from the subtrie. Child can never be nil here since the
		// subtrie must contain at least two other values with keys
		// longer than n.Key.
		dirty, child, err := t.deleteWithEpoch(n.Val, append(prefix, key[:len(n.Key)]...), key[len(n.Key):], epoch)
		if !t.renewNode(epoch, dirty, true) || err != nil {
			return false, n, err
		}
		switch child := child.(type) {
		case *shortNode:
			// The child shortNode is merged into its parent, track
			// is deleted as well.
			t.tracer.onDelete(append(prefix, n.Key...))

			// Deleting from the subtrie reduced it to another
			// short node. Merge the nodes to avoid creating a
			// shortNode{..., shortNode{...}}. Use concat (which
			// always creates a new slice) instead of append to
			// avoid modifying n.Key since it might be shared with
			// other nodes.
			return true, &shortNode{Key: concat(n.Key, child.Key...), Val: child.Val, flags: t.newFlag(), epoch: t.currentEpoch}, nil
		default:
			return true, &shortNode{Key: n.Key, Val: child, flags: t.newFlag(), epoch: t.currentEpoch}, nil
		}

	case *fullNode:
		dirty, nn, err := t.deleteWithEpoch(n.Children[key[0]], append(prefix, key[0]), key[1:], n.GetChildEpoch(int(key[0])))
		if !t.renewNode(epoch, dirty, true) || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn
		n.setEpoch(t.currentEpoch)
		n.UpdateChildEpoch(int(key[0]), t.currentEpoch)

		// Because n is a full node, it must've contained at least two children
		// before the delete operation. If the new child value is non-nil, n still
		// has at least two children after the deletion, and cannot be reduced to
		// a short node.
		if nn != nil {
			return true, n, nil
		}
		// Reduction:
		// Check how many non-nil entries are left after deleting and
		// reduce the full node to a short node if only one entry is
		// left. Since n must've contained at least two children
		// before deletion (otherwise it would not be a full node) n
		// can never be reduced to nil.
		//
		// When the loop is done, pos contains the index of the single
		// value that is left in n or -2 if n contains at least two
		// values.
		pos := -1
		for i, cld := range &n.Children {
			if cld != nil {
				if pos == -1 {
					pos = i
				} else {
					pos = -2
					break
				}
			}
		}
		if pos >= 0 {
			if pos != 16 {
				// If the remaining entry is a short node, it replaces
				// n and its key gets the missing nibble tacked to the
				// front. This avoids creating an invalid
				// shortNode{..., shortNode{...}}.  Since the entry
				// might not be loaded yet, resolve it just for this
				// check.
				cnode, err := t.resolve(n.Children[pos], append(prefix, byte(pos)))
				if err != nil {
					return false, nil, err
				}
				if cnode, ok := cnode.(*shortNode); ok {
					// Replace the entire full node with the short node.
					// Mark the original short node as deleted since the
					// value is embedded into the parent now.
					t.tracer.onDelete(append(prefix, byte(pos)))
					t.tracer.onDeleteBranchNode(prefix)

					k := append([]byte{byte(pos)}, cnode.Key...)
					return true, &shortNode{Key: k, Val: cnode.Val, flags: t.newFlag(), epoch: t.currentEpoch}, nil
				}
			}
			// Otherwise, n is replaced by a one-nibble short node
			// containing the child.
			t.tracer.onDeleteBranchNode(prefix)
			return true, &shortNode{Key: []byte{byte(pos)}, Val: n.Children[pos], flags: t.newFlag(), epoch: t.currentEpoch}, nil
		}
		// n still contains at least two values and cannot be reduced.
		return true, n, nil

	case valueNode:
		return true, nil, nil

	case nil:
		return false, nil, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and delete from it. This leaves all child nodes on
		// the path to the value in the trie.
		rn, err := t.resolveAndTrack(n, prefix)
		if err != nil {
			return false, nil, err
		}

		if child, ok := rn.(*fullNode); ok {
			if err = t.resolveEpochMeta(child, epoch, prefix); err != nil {
				return false, nil, err
			}
		}

		dirty, nn, err := t.deleteWithEpoch(rn, prefix, key, epoch)
		if !t.renewNode(epoch, dirty, true) || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v (%v)", n, n, key))
	}

}

func concat(s1 []byte, s2 ...byte) []byte {
	r := make([]byte, len(s1)+len(s2))
	copy(r, s1)
	copy(r[len(s1):], s2)
	return r
}

func (t *Trie) resolve(n node, prefix []byte) (node, error) {
	if n, ok := n.(hashNode); ok {
		return t.resolveAndTrack(n, prefix)
	}
	return n, nil
}

// resolveAndTrack loads node from the underlying store with the given node hash
// and path prefix and also tracks the loaded node blob in tracer treated as the
// node's original value. The rlp-encoded blob is preferred to be loaded from
// database because it's easy to decode node while complex to encode node to blob.
func (t *Trie) resolveAndTrack(n hashNode, prefix []byte) (node, error) {
	blob, err := t.reader.node(prefix, common.BytesToHash(n))
	if err != nil {
		return nil, err
	}
	t.tracer.onRead(prefix, blob)
	return mustDecodeNode(n, blob), nil
}

func (t *Trie) resolveHash(n hashNode, prefix []byte) (node, error) {
	blob, err := t.reader.node(prefix, common.BytesToHash(n))
	if err != nil {
		return nil, err
	}
	return mustDecodeNode(n, blob), nil
}

// resolveEpochMeta resolve full node's epoch map.
func (t *Trie) resolveEpochMeta(n node, epoch types.StateEpoch, prefix []byte) error {
	if !t.enableExpiry {
		return nil
	}
	// 1. Check if the node is a full node
	switch n := n.(type) {
	case *shortNode:
		n.setEpoch(epoch)
		return nil
	case *fullNode:
		n.setEpoch(epoch)
		meta, err := t.reader.epochMeta(prefix)
		if err != nil {
			return err
		}
		n.EpochMap = meta.EpochMap
		return nil
	case valueNode, hashNode, nil:
		// just skip
		return nil
	default:
		return errors.New("resolveShadowNode unsupported node type")
	}
}

// Hash returns the root hash of the trie. It does not write to the
// database and can be used even if the trie doesn't have one.
func (t *Trie) Hash() common.Hash {
	hash, cached := t.hashRoot()
	t.root = cached
	return common.BytesToHash(hash.(hashNode))
}

// Commit collects all dirty nodes in the trie and replaces them with the
// corresponding node hash. All collected nodes (including dirty leaves if
// collectLeaf is true) will be encapsulated into a nodeset for return.
// The returned nodeset can be nil if the trie is clean (nothing to commit).
// Once the trie is committed, it's not usable anymore. A new trie must
// be created with new root and updated trie database for following usage
func (t *Trie) Commit(collectLeaf bool) (common.Hash, *trienode.NodeSet, error) {
	defer t.tracer.reset()
	defer func() {
		// StateDB will cache the trie and reuse it to read and write,
		// the committed flag is true will prevent the cache trie access
		// the trie node.
		t.committed = false
	}()
	// Trie is empty and can be classified into two types of situations:
	// (a) The trie was empty and no update happens => return nil
	// (b) The trie was non-empty and all nodes are dropped => return
	//     the node set includes all deleted nodes
	if t.root == nil {
		paths := t.tracer.deletedNodes()
		if len(paths) == 0 {
			return types.EmptyRootHash, nil, nil // case (a)
		}
		nodes := trienode.NewNodeSet(t.owner)
		for _, path := range paths {
			nodes.AddNode([]byte(path), trienode.NewDeleted())
		}
		paths = t.tracer.deletedBranchNodes()
		for _, path := range paths {
			nodes.AddBranchNodeEpochMeta([]byte(path), nil)
		}
		return types.EmptyRootHash, nodes, nil // case (b)
	}
	// Derive the hash for all dirty nodes first. We hold the assumption
	// in the following procedure that all nodes are hashed.
	rootHash := t.Hash()

	// Do a quick check if we really need to commit. This can happen e.g.
	// if we load a trie for reading storage values, but don't write to it.
	if hashedNode, dirty := t.root.cache(); !dirty {
		// Replace the root node with the origin hash in order to
		// ensure all resolved nodes are dropped after the commit.
		t.root = hashedNode
		return rootHash, nil, nil
	}
	nodes := trienode.NewNodeSet(t.owner)
	for _, path := range t.tracer.deletedNodes() {
		nodes.AddNode([]byte(path), trienode.NewDeleted())
	}
	for _, path := range t.tracer.deletedBranchNodes() {
		nodes.AddBranchNodeEpochMeta([]byte(path), nil)
	}
	// store state expiry account meta
	if t.enableExpiry {
		if err := nodes.AddAccountMeta(types.NewMetaNoConsensus(t.rootEpoch)); err != nil {
			return common.Hash{}, nil, err
		}
	}
	t.root = newCommitter(nodes, t.tracer, collectLeaf, t.enableExpiry).Commit(t.root)
	return rootHash, nodes, nil
}

// hashRoot calculates the root hash of the given trie
func (t *Trie) hashRoot() (node, node) {
	if t.root == nil {
		return hashNode(types.EmptyRootHash.Bytes()), nil
	}
	// If the number of changes is below 100, we let one thread handle it
	h := newHasher(t.unhashed >= 100)
	defer func() {
		returnHasherToPool(h)
		t.unhashed = 0
	}()
	hashed, cached := h.hash(t.root, true)
	return hashed, cached
}

// Reset drops the referenced root node and cleans all internal state.
func (t *Trie) Reset() {
	t.root = nil
	t.owner = common.Hash{}
	t.unhashed = 0
	t.tracer.reset()
	t.committed = false
}

func (t *Trie) Size() int {
	return estimateSize(t.root)
}

// Owner returns the associated trie owner.
func (t *Trie) Owner() common.Hash {
	return t.owner
}

// TryRevive attempts to revive a trie from a list of MPTProofNubs.
// ReviveTrie performs full or partial revive and returns a list of successful
// nubs. ReviveTrie does not guarantee that a value will be revived completely,
// if the proof is not fully valid.
func (t *Trie) TryRevive(key []byte, proof []*MPTProofNub) ([]*MPTProofNub, error) {
	key = keybytesToHex(key)
	successNubs := make([]*MPTProofNub, 0, len(proof))
	reviveMeter.Mark(int64(len(proof)))
	// Revive trie with each proof nub
	for _, nub := range proof {
		rootExpired := types.EpochExpired(t.getRootEpoch(), t.currentEpoch)
		newNode, didRevive, err := t.tryRevive(t.root, key, nub.n1PrefixKey, *nub, 0, t.currentEpoch, rootExpired)
		if _, ok := err.(*ReviveNotExpiredError); ok {
			reviveNotExpiredMeter.Mark(1)
			continue
		}
		if err != nil {
			reviveErrMeter.Mark(1)
			return nil, err
		}
		if didRevive {
			successNubs = append(successNubs, nub)
			t.root = newNode
			t.rootEpoch = t.currentEpoch
		}
	}
	return successNubs, nil
}

func (t *Trie) tryRevive(n node, key []byte, targetPrefixKey []byte, nub MPTProofNub, pos int, epoch types.StateEpoch, isExpired bool) (node, bool, error) {

	if pos > len(targetPrefixKey) {
		return nil, false, fmt.Errorf("target revive node not found")
	}

	if pos == len(targetPrefixKey) {

		if !isExpired {
			return nil, false, NewReviveNotExpiredErr(key[:pos], epoch)
		}
		hn, ok := n.(hashNode)
		if !ok {
			return nil, false, fmt.Errorf("not match hashNode stub")
		}

		cachedHash, _ := nub.n1.cache()
		if !bytes.Equal(cachedHash, hn) {
			return nil, false, fmt.Errorf("hash values does not match")
		}

		if nub.n2 != nil {
			n1, ok := nub.n1.(*shortNode)
			if !ok {
				return nil, false, fmt.Errorf("invalid node type")
			}
			tryUpdateNodeEpoch(nub.n2, t.currentEpoch)
			newnode, _, err := t.updateChildNodeEpoch(nub.n2, key, pos+len(n1.Key), t.currentEpoch)
			if err != nil {
				return nil, false, fmt.Errorf("update child node epoch while reviving failed, err: %v", err)
			}
			n1 = n1.copy()
			n1.Val = newnode
			n1.flags = t.newFlag()
			tryUpdateNodeEpoch(n1, t.currentEpoch)
			renew, _, err := t.updateChildNodeEpoch(n1, key, pos, t.currentEpoch)
			if err != nil {
				return nil, false, fmt.Errorf("update child node epoch while reviving failed, err: %v", err)
			}
			return renew, true, nil
		}

		tryUpdateNodeEpoch(nub.n1, t.currentEpoch)
		newnode, _, err := t.updateChildNodeEpoch(nub.n1, key, pos, t.currentEpoch)
		if err != nil {
			return nil, false, fmt.Errorf("update child node epoch while reviving failed, err: %v", err)
		}

		return newnode, true, nil
	}

	if isExpired {
		return nil, false, NewExpiredNodeError(key[:pos], epoch)
	}

	switch n := n.(type) {
	case *shortNode:
		if len(key)-pos < len(n.Key) || !bytes.Equal(n.Key, key[pos:pos+len(n.Key)]) {
			return nil, false, fmt.Errorf("key %v not found", key)
		}
		newNode, didRevive, err := t.tryRevive(n.Val, key, targetPrefixKey, nub, pos+len(n.Key), epoch, isExpired)
		if didRevive && err == nil {
			n = n.copy()
			n.Val = newNode
			n.setEpoch(t.currentEpoch)
			n.flags = t.newFlag()
		}
		return n, didRevive, err
	case *fullNode:
		childIndex := int(key[pos])
		isExpired, _ := n.ChildExpired(nil, childIndex, t.currentEpoch)
		newNode, didRevive, err := t.tryRevive(n.Children[childIndex], key, targetPrefixKey, nub, pos+1, epoch, isExpired)
		if didRevive && err == nil {
			n = n.copy()
			n.Children[childIndex] = newNode
			n.setEpoch(t.currentEpoch)
			n.UpdateChildEpoch(childIndex, t.currentEpoch)
			n.flags = t.newFlag()
		}

		if e, ok := err.(*ExpiredNodeError); ok {
			e.Epoch = n.GetChildEpoch(childIndex)
			return n, didRevive, e
		}

		return n, didRevive, err
	case hashNode:
		child, err := t.resolveAndTrack(n, key[:pos])
		if err != nil {
			return nil, false, err
		}

		if child, ok := child.(*fullNode); ok {
			if err = t.resolveEpochMeta(child, epoch, key[:pos]); err != nil {
				return nil, false, err
			}
		}

		newNode, _, err := t.tryRevive(child, key, targetPrefixKey, nub, pos, epoch, isExpired)
		return newNode, true, err
	case nil:
		return nil, false, nil
	default:
		panic(fmt.Sprintf("invalid node: %T", n))
	}
}

// ExpireByPrefix is used to simulate the expiration of a trie by prefix key.
// It is not used in the actual trie implementation. ExpireByPrefix makes sure
// only a child node of a full node is expired, if not an error is returned.
func (t *Trie) ExpireByPrefix(prefixKeyHex []byte) error {
	hn, _, err := t.expireByPrefix(t.root, prefixKeyHex)
	if len(prefixKeyHex) == 0 && hn != nil { // whole trie is expired
		t.root = hn
		t.rootEpoch = 0
	}
	if err != nil {
		return err
	}
	return nil
}

func tryUpdateNodeEpoch(origin node, epoch types.StateEpoch) {
	switch n := origin.(type) {
	case *shortNode:
		n.setEpoch(epoch)
	case *fullNode:
		n.setEpoch(epoch)
	}
}

func (t *Trie) expireByPrefix(n node, prefixKeyHex []byte) (node, bool, error) {
	// Loop through prefix key
	// When prefix key is empty, generate the hash node of the current node
	// Replace current node with the hash node

	// If length of prefix key is empty
	if len(prefixKeyHex) == 0 {
		hasher := newHasher(false)
		defer returnHasherToPool(hasher)
		var hn node
		_, hn = hasher.proofHash(n)
		if _, ok := hn.(hashNode); ok {
			return hn, false, nil
		}

		return nil, true, nil
	}

	switch n := n.(type) {
	case *shortNode:
		matchLen := prefixLen(prefixKeyHex, n.Key)
		hn, didUpdateEpoch, err := t.expireByPrefix(n.Val, prefixKeyHex[matchLen:])
		if err != nil {
			return nil, didUpdateEpoch, err
		}

		if hn != nil {
			return nil, didUpdateEpoch, fmt.Errorf("can only expire child short node")
		}

		return nil, didUpdateEpoch, err
	case *fullNode:
		childIndex := int(prefixKeyHex[0])
		hn, didUpdateEpoch, err := t.expireByPrefix(n.Children[childIndex], prefixKeyHex[1:])
		if err != nil {
			return nil, didUpdateEpoch, err
		}

		// Replace child node with hash node
		if hn != nil {
			n.Children[prefixKeyHex[0]] = hn
		}

		// Update the epoch so that it is expired
		if !didUpdateEpoch {
			n.UpdateChildEpoch(childIndex, 0)
			didUpdateEpoch = true
		}

		return nil, didUpdateEpoch, err
	default:
		return nil, false, fmt.Errorf("invalid node type")
	}
}

func (t *Trie) getRootEpoch() types.StateEpoch {
	return t.rootEpoch
}

// renewNode check if renew node, according to trie node epoch and childDirty,
// childDirty or updateEpoch need copy for prevent reuse trie cache
func (t *Trie) renewNode(epoch types.StateEpoch, childDirty bool, updateEpoch bool) bool {
	// when !updateEpoch, it same as !t.withEpochMeta
	if !t.enableExpiry || !updateEpoch {
		return childDirty
	}

	// node need update epoch, just renew
	if t.currentEpoch > epoch {
		return true
	}

	// when no epoch update, same as before
	return childDirty
}

func (t *Trie) epochExpired(n node, epoch types.StateEpoch) bool {
	// when node is nil, skip epoch check
	if !t.enableExpiry || n == nil {
		return false
	}
	return types.EpochExpired(epoch, t.currentEpoch)
}

func (t *Trie) SetEpoch(epoch types.StateEpoch) {
	t.currentEpoch = epoch
}

type NodeInfo struct {
	Addr     common.Hash
	Path     []byte
	Hash     common.Hash
	Epoch    types.StateEpoch
	Key      common.Hash // only leaf has right Key.
	IsLeaf   bool
	IsBranch bool
}

// PruneExpired traverses the storage trie and prunes all expired nodes.
func (t *Trie) PruneExpired(pruneItemCh chan *NodeInfo, stats *atomic.Uint64) error {

	if !t.enableExpiry {
		return nil
	}

	if t.owner == (common.Hash{}) {
		return fmt.Errorf("cannot prune account trie")
	}

	err := t.findExpiredSubTree(t.root, nil, t.getRootEpoch(), func(n node, path []byte, epoch types.StateEpoch) {
		if pruneErr := t.recursePruneExpiredNode(n, path, epoch, pruneItemCh); pruneErr != nil {
			log.Error("recursePruneExpiredNode err", "Path", path, "err", pruneErr)
		}
	}, stats)
	if err != nil {
		return err
	}

	return nil
}

func (t *Trie) findExpiredSubTree(n node, path []byte, epoch types.StateEpoch, pruner func(n node, path []byte, epoch types.StateEpoch), stats *atomic.Uint64) error {
	// Upon reaching expired node, it will recursively traverse downwards to all the child nodes
	// and collect their hashes. Then, the corresponding key-value pairs will be deleted from the
	// database by batches.
	if t.epochExpired(n, epoch) {
		pruner(n, path, epoch)
		return nil
	}

	switch n := n.(type) {
	case *shortNode:
		if stats != nil {
			stats.Add(1)
		}
		err := t.findExpiredSubTree(n.Val, append(path, n.Key...), epoch, pruner, stats)
		if err != nil {
			return err
		}
		return nil
	case *fullNode:
		if stats != nil {
			stats.Add(1)
		}
		var err error
		// Go through every child and recursively delete expired nodes
		for i, child := range n.Children {
			err = t.findExpiredSubTree(child, append(path, byte(i)), n.GetChildEpoch(i), pruner, stats)
			if err != nil {
				return err
			}
		}
		return nil

	case hashNode:
		resolve, err := t.resolveAndTrack(n, path)
		if _, ok := err.(*MissingNodeError); ok {
			return nil
		}
		if err != nil {
			return err
		}
		if err = t.resolveEpochMeta(resolve, epoch, path); err != nil {
			return err
		}

		return t.findExpiredSubTree(resolve, path, epoch, pruner, stats)
	case valueNode:
		return nil
	case nil:
		return nil
	default:
		panic(fmt.Sprintf("invalid node type: %T", n))
	}
}

func (t *Trie) recursePruneExpiredNode(n node, path []byte, epoch types.StateEpoch, pruneItemCh chan *NodeInfo) error {
	switch n := n.(type) {
	case *shortNode:
		key := common.Hash{}
		_, ok := n.Val.(valueNode)
		if ok {
			key = common.BytesToHash(hexToKeybytes(append(path, n.Key...)))
		}
		err := t.recursePruneExpiredNode(n.Val, append(path, n.Key...), epoch, pruneItemCh)
		if err != nil {
			return err
		}
		// prune child first
		pruneItemCh <- &NodeInfo{
			Addr:   t.owner,
			Hash:   common.BytesToHash(n.flags.hash),
			Path:   path,
			Key:    key,
			Epoch:  epoch,
			IsLeaf: ok,
		}
		return nil
	case *fullNode:
		// recurse child, and except valueNode
		for i := 0; i < BranchNodeLength-1; i++ {
			err := t.recursePruneExpiredNode(n.Children[i], append(path, byte(i)), n.EpochMap[i], pruneItemCh)
			if err != nil {
				return err
			}
		}
		// prune child first
		pruneItemCh <- &NodeInfo{
			Addr:     t.owner,
			Hash:     common.BytesToHash(n.flags.hash),
			Path:     path,
			Epoch:    epoch,
			IsBranch: true,
		}
		return nil
	case hashNode:
		// hashNode is a index of trie node storage, need not prune.
		resolve, err := t.resolveAndTrack(n, path)
		if err != nil {
			return err
		}
		if err = t.resolveEpochMeta(resolve, epoch, path); err != nil {
			return err
		}
		return t.recursePruneExpiredNode(resolve, path, epoch, pruneItemCh)
	case valueNode:
		// value node is not a single storage uint, so pass to prune.
		return nil
	case nil:
		return nil
	default:
		panic(fmt.Sprintf("invalid node type: %T", n))
	}
}
