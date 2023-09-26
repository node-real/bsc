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
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// Prove constructs a merkle proof for key. The result contains all encoded nodes
// on the path to the value at key. The value itself is also included in the last
// node and can be retrieved by verifying the proof.
//
// If the trie does not contain a value for key, the returned proof contains all
// nodes of the longest existing prefix of the key (at least the root node), ending
// with the node that proves the absence of the key.
func (t *Trie) Prove(key []byte, proofDb ethdb.KeyValueWriter) error {
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return ErrCommitted
	}
	// Collect all nodes on the path to key.
	var (
		prefix []byte
		nodes  []node
		tn     = t.root
	)
	key = keybytesToHex(key)
	for len(key) > 0 && tn != nil {
		switch n := tn.(type) {
		case *shortNode:
			if len(key) < len(n.Key) || !bytes.Equal(n.Key, key[:len(n.Key)]) {
				// The trie doesn't contain the key.
				tn = nil
			} else {
				tn = n.Val
				prefix = append(prefix, n.Key...)
				key = key[len(n.Key):]
			}
			nodes = append(nodes, n)
		case *fullNode:
			tn = n.Children[key[0]]
			prefix = append(prefix, key[0])
			key = key[1:]
			nodes = append(nodes, n)
		case hashNode:
			// Retrieve the specified node from the underlying node reader.
			// trie.resolveAndTrack is not used since in that function the
			// loaded blob will be tracked, while it's not required here since
			// all loaded nodes won't be linked to trie at all and track nodes
			// may lead to out-of-memory issue.
			blob, err := t.reader.node(prefix, common.BytesToHash(n))
			if err != nil {
				log.Error("Unhandled trie error in Trie.Prove", "err", err)
				return err
			}
			// The raw-blob format nodes are loaded either from the
			// clean cache or the database, they are all in their own
			// copy and safe to use unsafe decoder.
			tn = mustDecodeNodeUnsafe(n, blob)
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", tn, tn))
		}
	}
	hasher := newHasher(false)
	defer returnHasherToPool(hasher)

	for i, n := range nodes {
		var hn node
		n, hn = hasher.proofHash(n)
		if hash, ok := hn.(hashNode); ok || i == 0 {
			// If the node's database encoding is a hash (or is the
			// root node), it becomes a proof element.
			enc := nodeToBytes(n)
			if !ok {
				hash = hasher.hashData(enc)
			}
			proofDb.Put(hash, enc)
		}
	}
	return nil
}

// Prove constructs a merkle proof for key. The result contains all encoded nodes
// on the path to the value at key. The value itself is also included in the last
// node and can be retrieved by verifying the proof.
//
// If the trie does not contain a value for key, the returned proof contains all
// nodes of the longest existing prefix of the key (at least the root node), ending
// with the node that proves the absence of the key.
func (t *StateTrie) Prove(key []byte, proofDb ethdb.KeyValueWriter) error {
	return t.trie.Prove(key, proofDb)
}

// traverseNodes traverses the trie with the given key starting at the given node.
// If the trie contains the key, the returned node is the node that contains the
// value for the key. If nodes is specified, the traversed nodes are appended to
// it.
func (t *Trie) traverseNodes(tn node, prefixKey, suffixKey []byte, nodes *[]node, epoch types.StateEpoch, updateEpoch bool) (node, error) {
	for len(suffixKey) > 0 && tn != nil {
		log.Info("traverseNodes loop", "prefix", common.Bytes2Hex(prefixKey), "suffix", common.Bytes2Hex(suffixKey), "n", tn.fstring(""))
		switch n := tn.(type) {
		case *shortNode:
			if len(suffixKey) >= len(n.Key) && bytes.Equal(n.Key, suffixKey[:len(n.Key)]) {
				tn = n.Val
				prefixKey = append(prefixKey, n.Key...)
				suffixKey = suffixKey[len(n.Key):]
				if nodes != nil {
					*nodes = append(*nodes, n)
				}
				continue
			}

			tn = nil
			if nodes != nil {
				*nodes = append(*nodes, n)
			}
			// if there is a extern node, must put the val
			hn, isExternNode := n.Val.(hashNode)
			if isExternNode && nodes != nil {
				prefixKey = append(prefixKey, n.Key...)
				nextBlob, err := t.reader.node(prefixKey, common.BytesToHash(hn))
				if err != nil {
					log.Error("Unhandled next trie error in traverseNodes", "err", err)
					return nil, err
				}
				next := mustDecodeNodeUnsafe(hn, nextBlob)
				*nodes = append(*nodes, next)
			}
		case *fullNode:
			tn = n.Children[suffixKey[0]]
			prefixKey = append(prefixKey, suffixKey[0])
			suffixKey = suffixKey[1:]
			if nodes != nil {
				*nodes = append(*nodes, n)
			}
		case hashNode:
			// Retrieve the specified node from the underlying node reader.
			// trie.resolveAndTrack is not used since in that function the
			// loaded blob will be tracked, while it's not required here since
			// all loaded nodes won't be linked to trie at all and track nodes
			// may lead to out-of-memory issue.
			blob, err := t.reader.node(prefixKey, common.BytesToHash(n))
			if err != nil {
				log.Error("Unhandled trie error in traverseNodes", "err", err)
				return nil, err
			}
			// The raw-blob format nodes are loaded either from the
			// clean cache or the database, they are all in their own
			// copy and safe to use unsafe decoder.
			tn = mustDecodeNodeUnsafe(n, blob)
			if err = t.resolveEpochMeta(tn, epoch, prefixKey); err != nil {
				return nil, err
			}
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", tn, tn))
		}
	}

	return tn, nil
}

func (t *Trie) ProvePath(key []byte, prefixKeyHex []byte, proofDb ethdb.KeyValueWriter) error {

	if t.committed {
		return ErrCommitted
	}

	if len(key) == 0 {
		return fmt.Errorf("key is empty")
	}

	key = keybytesToHex(key)

	// traverse down using the prefixKeyHex
	var nodes []node
	tn := t.root
	startNode, err := t.traverseNodes(tn, nil, prefixKeyHex, nil, 0, false) // obtain the node where the prefixKeyHex leads to
	if err != nil {
		return err
	}

	key = key[len(prefixKeyHex):] // obtain the suffix key

	// traverse through the suffix key
	_, err = t.traverseNodes(startNode, prefixKeyHex, key, &nodes, 0, false)
	if err != nil {
		return err
	}

	if len(nodes) == 0 {
		log.Error("found nothing....", "prefix", prefixKeyHex, "key", key)
		return fmt.Errorf("cannot find target proof, prefix: %#x, suffix: %#x", prefixKeyHex, key)
	}

	hasher := newHasher(false)
	defer returnHasherToPool(hasher)

	// construct the proof
	for _, n := range nodes {
		var hn node
		n, hn = hasher.proofHash(n)
		if hash, ok := hn.(hashNode); ok {
			enc := nodeToBytes(n)
			if !ok {
				hash = hasher.hashData(enc)
			}
			proofDb.Put(hash, enc)
		}
	}

	return nil
}

// VerifyPathProof reconstructs the trie from the given proof and verifies the root hash.
func VerifyPathProof(keyHex []byte, prefixKeyHex []byte, proofList [][]byte, epoch types.StateEpoch) (node, hashNode, error) {

	if len(proofList) == 0 {
		return nil, nil, fmt.Errorf("proof list is empty")
	}

	n, err := ConstructTrieFromProof(keyHex, prefixKeyHex, proofList, epoch)
	if err != nil {
		return nil, nil, err
	}

	// hash the root node
	hasher := newHasher(false)
	defer returnHasherToPool(hasher)
	hn, cn := hasher.hash(n, true)
	if hash, ok := hn.(hashNode); ok {
		return cn, hash, nil
	}

	return nil, nil, fmt.Errorf("path proof verification failed")
}

// ConstructTrieFromProof constructs a trie from the given proof. It returns the root node of the trie.
func ConstructTrieFromProof(keyHex []byte, prefixKeyHex []byte, proofList [][]byte, epoch types.StateEpoch) (node, error) {
	if len(proofList) == 0 {
		return nil, nil
	}
	h := newHasher(false)
	defer returnHasherToPool(h)
	keyHex = keyHex[len(prefixKeyHex):]

	root, err := decodeNode(nil, proofList[0])
	if err != nil {
		return nil, fmt.Errorf("decode proof root %#x, err: %v", proofList[0], err)
	}
	// update epoch
	switch n := root.(type) {
	case *shortNode:
		n.setEpoch(epoch)
	case *fullNode:
		n.setEpoch(epoch)
	}

	parentNode := root
	for i := 1; i < len(proofList); i++ {
		n, err := decodeNode(nil, proofList[i])
		if err != nil {
			return nil, fmt.Errorf("decode proof item %#x, err: %v", proofList[i], err)
		}

		// verify proof continuous
		keyrest, child := get(parentNode, keyHex, false)
		switch cld := child.(type) {
		case nil:
			return nil, NewKeyDoesNotExistError(keyHex)
		case hashNode:
			hashed, _ := h.hash(n, false)
			if !bytes.Equal(cld, hashed.(hashNode)) {
				return nil, fmt.Errorf("the child node of shortNode is not a hashNode or doesn't match the hash in the proof")
			}
		default:
			// proof's child cannot contain valueNode/shortNode/fullNode
			return nil, fmt.Errorf("worng proof, got unexpect node, fstr: %v", child.fstring(""))
		}

		// update epoch
		switch n := n.(type) {
		case *shortNode:
			n.setEpoch(epoch)
		case *fullNode:
			n.setEpoch(epoch)
		}

		// Link the parent and child.
		switch sn := parentNode.(type) {
		case *shortNode:
			sn.Val = n
		case *fullNode:
			sn.Children[keyHex[0]] = n
			sn.UpdateChildEpoch(int(keyHex[0]), epoch)
		}

		// reset
		parentNode = n
		keyHex = keyrest
	}

	return root, nil
}

// updateEpochInChildNodes traverse down a node and update the epoch of the child nodes
func updateEpochInChildNodes(tn *node, key []byte, epoch types.StateEpoch) error {

	node := *tn
	startNode := node

	for len(key) > 0 && node != nil {
		switch n := node.(type) {
		case *shortNode:
			if len(key) < len(n.Key) || !bytes.Equal(n.Key, key[:len(n.Key)]) {
				// The trie doesn't contain the key.
				node = nil
			} else {
				node = n.Val
				key = key[len(n.Key):]
			}
			n.setEpoch(epoch)
		case *fullNode:
			node = n.Children[key[0]]
			n.UpdateChildEpoch(int(key[0]), epoch)
			n.setEpoch(epoch)

			key = key[1:]
		case nil, hashNode, valueNode:
			*tn = startNode
			return nil
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", tn, tn))
		}
	}

	*tn = startNode

	return nil
}

func (t *StateTrie) ProvePath(key []byte, path []byte, proofDb ethdb.KeyValueWriter) error {
	return t.trie.ProvePath(key, path, proofDb)
}

// VerifyProof checks merkle proofs. The given proof must contain the value for
// key in a trie with the given root hash. VerifyProof returns an error if the
// proof contains invalid trie nodes or the wrong value.
func VerifyProof(rootHash common.Hash, key []byte, proofDb ethdb.KeyValueReader) (value []byte, err error) {
	key = keybytesToHex(key)
	wantHash := rootHash
	for i := 0; ; i++ {
		buf, _ := proofDb.Get(wantHash[:])
		if buf == nil {
			return nil, fmt.Errorf("proof node %d (hash %064x) missing", i, wantHash)
		}
		n, err := decodeNode(wantHash[:], buf)
		if err != nil {
			return nil, fmt.Errorf("bad proof node %d: %v", i, err)
		}
		keyrest, cld := get(n, key, true)
		switch cld := cld.(type) {
		case nil:
			// The trie doesn't contain the key.
			return nil, nil
		case hashNode:
			key = keyrest
			copy(wantHash[:], cld)
		case valueNode:
			return cld, nil
		}
	}
}

// proofToPath converts a merkle proof to trie node path. The main purpose of
// this function is recovering a node path from the merkle proof stream. All
// necessary nodes will be resolved and leave the remaining as hashnode.
//
// The given edge proof is allowed to be an existent or non-existent proof.
func proofToPath(rootHash common.Hash, root node, key []byte, proofDb ethdb.KeyValueReader, allowNonExistent bool) (node, []byte, error) {
	// resolveNode retrieves and resolves trie node from merkle proof stream
	resolveNode := func(hash common.Hash) (node, error) {
		buf, _ := proofDb.Get(hash[:])
		if buf == nil {
			return nil, fmt.Errorf("proof node (hash %064x) missing", hash)
		}
		n, err := decodeNode(hash[:], buf)
		if err != nil {
			return nil, fmt.Errorf("bad proof node %v", err)
		}
		return n, err
	}
	// If the root node is empty, resolve it first.
	// Root node must be included in the proof.
	if root == nil {
		n, err := resolveNode(rootHash)
		if err != nil {
			return nil, nil, err
		}
		root = n
	}
	var (
		err           error
		child, parent node
		keyrest       []byte
		valnode       []byte
	)
	key, parent = keybytesToHex(key), root
	for {
		keyrest, child = get(parent, key, false)
		switch cld := child.(type) {
		case nil:
			// The trie doesn't contain the key. It's possible
			// the proof is a non-existing proof, but at least
			// we can prove all resolved nodes are correct, it's
			// enough for us to prove range.
			if allowNonExistent {
				return root, nil, nil
			}
			return nil, nil, errors.New("the node is not contained in trie")
		case *shortNode:
			key, parent = keyrest, child // Already resolved
			continue
		case *fullNode:
			key, parent = keyrest, child // Already resolved
			continue
		case hashNode:
			child, err = resolveNode(common.BytesToHash(cld))
			if err != nil {
				return nil, nil, err
			}
		case valueNode:
			valnode = cld
		}
		// Link the parent and child.
		switch pnode := parent.(type) {
		case *shortNode:
			pnode.Val = child
		case *fullNode:
			pnode.Children[key[0]] = child
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", pnode, pnode))
		}
		if len(valnode) > 0 {
			return root, valnode, nil // The whole path is resolved
		}
		key, parent = keyrest, child
	}
}

// unsetInternal removes all internal node references(hashnode, embedded node).
// It should be called after a trie is constructed with two edge paths. Also
// the given boundary keys must be the one used to construct the edge paths.
//
// It's the key step for range proof. All visited nodes should be marked dirty
// since the node content might be modified. Besides it can happen that some
// fullnodes only have one child which is disallowed. But if the proof is valid,
// the missing children will be filled, otherwise it will be thrown anyway.
//
// Note we have the assumption here the given boundary keys are different
// and right is larger than left.
func unsetInternal(n node, left []byte, right []byte) (bool, error) {
	left, right = keybytesToHex(left), keybytesToHex(right)

	// Step down to the fork point. There are two scenarios can happen:
	// - the fork point is a shortnode: either the key of left proof or
	//   right proof doesn't match with shortnode's key.
	// - the fork point is a fullnode: both two edge proofs are allowed
	//   to point to a non-existent key.
	var (
		pos    = 0
		parent node

		// fork indicator, 0 means no fork, -1 means proof is less, 1 means proof is greater
		shortForkLeft, shortForkRight int
	)
findFork:
	for {
		switch rn := (n).(type) {
		case *shortNode:
			rn.flags = nodeFlag{dirty: true}

			// If either the key of left proof or right proof doesn't match with
			// shortnode, stop here and the forkpoint is the shortnode.
			if len(left)-pos < len(rn.Key) {
				shortForkLeft = bytes.Compare(left[pos:], rn.Key)
			} else {
				shortForkLeft = bytes.Compare(left[pos:pos+len(rn.Key)], rn.Key)
			}
			if len(right)-pos < len(rn.Key) {
				shortForkRight = bytes.Compare(right[pos:], rn.Key)
			} else {
				shortForkRight = bytes.Compare(right[pos:pos+len(rn.Key)], rn.Key)
			}
			if shortForkLeft != 0 || shortForkRight != 0 {
				break findFork
			}
			parent = n
			n, pos = rn.Val, pos+len(rn.Key)
		case *fullNode:
			rn.flags = nodeFlag{dirty: true}

			// If either the node pointed by left proof or right proof is nil,
			// stop here and the forkpoint is the fullnode.
			leftnode, rightnode := rn.Children[left[pos]], rn.Children[right[pos]]
			if leftnode == nil || rightnode == nil || leftnode != rightnode {
				break findFork
			}
			parent = n
			n, pos = rn.Children[left[pos]], pos+1
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", n, n))
		}
	}
	switch rn := n.(type) {
	case *shortNode:
		// There can have these five scenarios:
		// - both proofs are less than the trie path => no valid range
		// - both proofs are greater than the trie path => no valid range
		// - left proof is less and right proof is greater => valid range, unset the shortnode entirely
		// - left proof points to the shortnode, but right proof is greater
		// - right proof points to the shortnode, but left proof is less
		if shortForkLeft == -1 && shortForkRight == -1 {
			return false, errors.New("empty range")
		}
		if shortForkLeft == 1 && shortForkRight == 1 {
			return false, errors.New("empty range")
		}
		if shortForkLeft != 0 && shortForkRight != 0 {
			// The fork point is root node, unset the entire trie
			if parent == nil {
				return true, nil
			}
			parent.(*fullNode).Children[left[pos-1]] = nil
			return false, nil
		}
		// Only one proof points to non-existent key.
		if shortForkRight != 0 {
			if _, ok := rn.Val.(valueNode); ok {
				// The fork point is root node, unset the entire trie
				if parent == nil {
					return true, nil
				}
				parent.(*fullNode).Children[left[pos-1]] = nil
				return false, nil
			}
			return false, unset(rn, rn.Val, left[pos:], len(rn.Key), false)
		}
		if shortForkLeft != 0 {
			if _, ok := rn.Val.(valueNode); ok {
				// The fork point is root node, unset the entire trie
				if parent == nil {
					return true, nil
				}
				parent.(*fullNode).Children[right[pos-1]] = nil
				return false, nil
			}
			return false, unset(rn, rn.Val, right[pos:], len(rn.Key), true)
		}
		return false, nil
	case *fullNode:
		// unset all internal nodes in the forkpoint
		for i := left[pos] + 1; i < right[pos]; i++ {
			rn.Children[i] = nil
		}
		if err := unset(rn, rn.Children[left[pos]], left[pos:], 1, false); err != nil {
			return false, err
		}
		if err := unset(rn, rn.Children[right[pos]], right[pos:], 1, true); err != nil {
			return false, err
		}
		return false, nil
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// unset removes all internal node references either the left most or right most.
// It can meet these scenarios:
//
//   - The given path is existent in the trie, unset the associated nodes with the
//     specific direction
//   - The given path is non-existent in the trie
//   - the fork point is a fullnode, the corresponding child pointed by path
//     is nil, return
//   - the fork point is a shortnode, the shortnode is included in the range,
//     keep the entire branch and return.
//   - the fork point is a shortnode, the shortnode is excluded in the range,
//     unset the entire branch.
func unset(parent node, child node, key []byte, pos int, removeLeft bool) error {
	switch cld := child.(type) {
	case *fullNode:
		if removeLeft {
			for i := 0; i < int(key[pos]); i++ {
				cld.Children[i] = nil
			}
			cld.flags = nodeFlag{dirty: true}
		} else {
			for i := key[pos] + 1; i < 16; i++ {
				cld.Children[i] = nil
			}
			cld.flags = nodeFlag{dirty: true}
		}
		return unset(cld, cld.Children[key[pos]], key, pos+1, removeLeft)
	case *shortNode:
		if len(key[pos:]) < len(cld.Key) || !bytes.Equal(cld.Key, key[pos:pos+len(cld.Key)]) {
			// Find the fork point, it's an non-existent branch.
			if removeLeft {
				if bytes.Compare(cld.Key, key[pos:]) < 0 {
					// The key of fork shortnode is less than the path
					// (it belongs to the range), unset the entire
					// branch. The parent must be a fullnode.
					fn := parent.(*fullNode)
					fn.Children[key[pos-1]] = nil
				}
				//else {
				// The key of fork shortnode is greater than the
				// path(it doesn't belong to the range), keep
				// it with the cached hash available.
				//}
			} else {
				if bytes.Compare(cld.Key, key[pos:]) > 0 {
					// The key of fork shortnode is greater than the
					// path(it belongs to the range), unset the entrie
					// branch. The parent must be a fullnode.
					fn := parent.(*fullNode)
					fn.Children[key[pos-1]] = nil
				}
				//else {
				// The key of fork shortnode is less than the
				// path(it doesn't belong to the range), keep
				// it with the cached hash available.
				//}
			}
			return nil
		}
		if _, ok := cld.Val.(valueNode); ok {
			fn := parent.(*fullNode)
			fn.Children[key[pos-1]] = nil
			return nil
		}
		cld.flags = nodeFlag{dirty: true}
		return unset(cld, cld.Val, key, pos+len(cld.Key), removeLeft)
	case nil:
		// If the node is nil, then it's a child of the fork point
		// fullnode(it's a non-existent branch).
		return nil
	default:
		panic("it shouldn't happen") // hashNode, valueNode
	}
}

// hasRightElement returns the indicator whether there exists more elements
// on the right side of the given path. The given path can point to an existent
// key or a non-existent one. This function has the assumption that the whole
// path should already be resolved.
func hasRightElement(node node, key []byte) bool {
	pos, key := 0, keybytesToHex(key)
	for node != nil {
		switch rn := node.(type) {
		case *fullNode:
			for i := key[pos] + 1; i < 16; i++ {
				if rn.Children[i] != nil {
					return true
				}
			}
			node, pos = rn.Children[key[pos]], pos+1
		case *shortNode:
			if len(key)-pos < len(rn.Key) || !bytes.Equal(rn.Key, key[pos:pos+len(rn.Key)]) {
				return bytes.Compare(rn.Key, key[pos:]) > 0
			}
			node, pos = rn.Val, pos+len(rn.Key)
		case valueNode:
			return false // We have resolved the whole path
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", node, node)) // hashnode
		}
	}
	return false
}

// VerifyRangeProof checks whether the given leaf nodes and edge proof
// can prove the given trie leaves range is matched with the specific root.
// Besides, the range should be consecutive (no gap inside) and monotonic
// increasing.
//
// Note the given proof actually contains two edge proofs. Both of them can
// be non-existent proofs. For example the first proof is for a non-existent
// key 0x03, the last proof is for a non-existent key 0x10. The given batch
// leaves are [0x04, 0x05, .. 0x09]. It's still feasible to prove the given
// batch is valid.
//
// The firstKey is paired with firstProof, not necessarily the same as keys[0]
// (unless firstProof is an existent proof). Similarly, lastKey and lastProof
// are paired.
//
// Expect the normal case, this function can also be used to verify the following
// range proofs:
//
//   - All elements proof. In this case the proof can be nil, but the range should
//     be all the leaves in the trie.
//
//   - One element proof. In this case no matter the edge proof is a non-existent
//     proof or not, we can always verify the correctness of the proof.
//
//   - Zero element proof. In this case a single non-existent proof is enough to prove.
//     Besides, if there are still some other leaves available on the right side, then
//     an error will be returned.
//
// Except returning the error to indicate the proof is valid or not, the function will
// also return a flag to indicate whether there exists more accounts/slots in the trie.
//
// Note: This method does not verify that the proof is of minimal form. If the input
// proofs are 'bloated' with neighbour leaves or random data, aside from the 'useful'
// data, then the proof will still be accepted.
func VerifyRangeProof(rootHash common.Hash, firstKey []byte, lastKey []byte, keys [][]byte, values [][]byte, proof ethdb.KeyValueReader) (bool, error) {
	if len(keys) != len(values) {
		return false, fmt.Errorf("inconsistent proof data, keys: %d, values: %d", len(keys), len(values))
	}
	// Ensure the received batch is monotonic increasing and contains no deletions
	for i := 0; i < len(keys)-1; i++ {
		if bytes.Compare(keys[i], keys[i+1]) >= 0 {
			return false, errors.New("range is not monotonically increasing")
		}
	}
	for _, value := range values {
		if len(value) == 0 {
			return false, errors.New("range contains deletion")
		}
	}
	// Special case, there is no edge proof at all. The given range is expected
	// to be the whole leaf-set in the trie.
	if proof == nil {
		tr := NewStackTrie(nil)
		for index, key := range keys {
			tr.Update(key, values[index])
		}
		if have, want := tr.Hash(), rootHash; have != want {
			return false, fmt.Errorf("invalid proof, want hash %x, got %x", want, have)
		}
		return false, nil // No more elements
	}
	// Special case, there is a provided edge proof but zero key/value
	// pairs, ensure there are no more accounts / slots in the trie.
	if len(keys) == 0 {
		root, val, err := proofToPath(rootHash, nil, firstKey, proof, true)
		if err != nil {
			return false, err
		}
		if val != nil || hasRightElement(root, firstKey) {
			return false, errors.New("more entries available")
		}
		return false, nil
	}
	// Special case, there is only one element and two edge keys are same.
	// In this case, we can't construct two edge paths. So handle it here.
	if len(keys) == 1 && bytes.Equal(firstKey, lastKey) {
		root, val, err := proofToPath(rootHash, nil, firstKey, proof, false)
		if err != nil {
			return false, err
		}
		if !bytes.Equal(firstKey, keys[0]) {
			return false, errors.New("correct proof but invalid key")
		}
		if !bytes.Equal(val, values[0]) {
			return false, errors.New("correct proof but invalid data")
		}
		return hasRightElement(root, firstKey), nil
	}
	// Ok, in all other cases, we require two edge paths available.
	// First check the validity of edge keys.
	if bytes.Compare(firstKey, lastKey) >= 0 {
		return false, errors.New("invalid edge keys")
	}
	// todo(rjl493456442) different length edge keys should be supported
	if len(firstKey) != len(lastKey) {
		return false, errors.New("inconsistent edge keys")
	}
	// Convert the edge proofs to edge trie paths. Then we can
	// have the same tree architecture with the original one.
	// For the first edge proof, non-existent proof is allowed.
	root, _, err := proofToPath(rootHash, nil, firstKey, proof, true)
	if err != nil {
		return false, err
	}
	// Pass the root node here, the second path will be merged
	// with the first one. For the last edge proof, non-existent
	// proof is also allowed.
	root, _, err = proofToPath(rootHash, root, lastKey, proof, true)
	if err != nil {
		return false, err
	}
	// Remove all internal references. All the removed parts should
	// be re-filled(or re-constructed) by the given leaves range.
	empty, err := unsetInternal(root, firstKey, lastKey)
	if err != nil {
		return false, err
	}
	// Rebuild the trie with the leaf stream, the shape of trie
	// should be same with the original one.
	tr := &Trie{root: root, reader: newEmptyReader(), tracer: newTracer()}
	if empty {
		tr.root = nil
	}
	for index, key := range keys {
		tr.Update(key, values[index])
	}
	if tr.Hash() != rootHash {
		return false, fmt.Errorf("invalid proof, want hash %x, got %x", rootHash, tr.Hash())
	}
	return hasRightElement(tr.root, keys[len(keys)-1]), nil
}

// get returns the child of the given node. Return nil if the
// node with specified key doesn't exist at all.
//
// There is an additional flag `skipResolved`. If it's set then
// all resolved nodes won't be returned.
func get(tn node, key []byte, skipResolved bool) ([]byte, node) {
	for {
		switch n := tn.(type) {
		case *shortNode:
			if len(key) < len(n.Key) || !bytes.Equal(n.Key, key[:len(n.Key)]) {
				return nil, nil
			}
			tn = n.Val
			key = key[len(n.Key):]
			if !skipResolved {
				return key, tn
			}
		case *fullNode:
			tn = n.Children[key[0]]
			key = key[1:]
			if !skipResolved {
				return key, tn
			}
		case hashNode:
			return key, n
		case nil:
			return key, nil
		case valueNode:
			return nil, n
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", tn, tn))
		}
	}
}

type MPTProof struct {
	RootKeyHex []byte   // prefix key in nibbles format, max 65 bytes. TODO: optimize witness size
	Proof      [][]byte // list of RLP-encoded nodes
}

type MPTProofNub struct {
	n1PrefixKey []byte // n1's prefix hex key, max 64bytes
	n1          node
	n2PrefixKey []byte // n2's prefix hex key, max 64bytes
	n2          node
}

// ResolveKV revive state could revive KV from fullNode[0-15] or fullNode[16] or shortNode.Val, return KVs for cache & snap
func (m *MPTProofNub) ResolveKV() (map[string][]byte, error) {
	kvMap := make(map[string][]byte)
	if err := resolveKV(m.n1, m.n1PrefixKey, kvMap); err != nil {
		return nil, err
	}
	if err := resolveKV(m.n2, m.n2PrefixKey, kvMap); err != nil {
		return nil, err
	}

	return kvMap, nil
}

func (m *MPTProofNub) GetValue() []byte {
	if val := getNubValue(m.n1, m.n1PrefixKey); val != nil {
		return val
	}

	if val := getNubValue(m.n2, m.n2PrefixKey); val != nil {
		return val
	}

	return nil
}

func (m *MPTProofNub) String() string {
	buf := bytes.NewBuffer(nil)
	buf.WriteString("n1: ")
	buf.WriteString(hex.EncodeToString(m.n1PrefixKey))
	buf.WriteString(", n1proof: ")
	if m.n1 != nil {
		buf.WriteString(m.n1.fstring(""))
	}
	buf.WriteString(", n2: ")
	buf.WriteString(hex.EncodeToString(m.n2PrefixKey))
	buf.WriteString(", n2proof: ")
	if m.n2 != nil {
		buf.WriteString(m.n2.fstring(""))
	}
	return buf.String()
}

func getNubValue(origin node, prefixKey []byte) []byte {
	switch n := origin.(type) {
	case nil, hashNode:
		return nil
	case valueNode:
		_, content, _, _ := rlp.Split(n)
		return content
	case *shortNode:
		return getNubValue(n.Val, append(prefixKey, n.Key...))
	case *fullNode:
		for i := 0; i < BranchNodeLength-1; i++ {
			if val := getNubValue(n.Children[i], append(prefixKey, byte(i))); val != nil {
				return val
			}
		}
		return getNubValue(n.Children[BranchNodeLength-1], prefixKey)
	default:
		panic(fmt.Sprintf("invalid node: %v", origin))
	}
}

func resolveKV(origin node, prefixKey []byte, kvWriter map[string][]byte) error {
	switch n := origin.(type) {
	case nil, hashNode:
		return nil
	case valueNode:
		_, content, _, err := rlp.Split(n)
		if err != nil {
			return err
		}
		kvWriter[string(hexToKeybytes(prefixKey))] = content
		return nil
	case *shortNode:
		return resolveKV(n.Val, append(prefixKey, n.Key...), kvWriter)
	case *fullNode:
		for i := 0; i < BranchNodeLength-1; i++ {
			if err := resolveKV(n.Children[i], append(prefixKey, byte(i)), kvWriter); err != nil {
				return err
			}
		}
		return resolveKV(n.Children[BranchNodeLength-1], prefixKey, kvWriter)
	default:
		panic(fmt.Sprintf("invalid node: %v", origin))
	}
}

type MPTProofCache struct {
	MPTProof

	cacheHexPath [][]byte       // cache path for performance
	cacheHashes  [][]byte       // cache hash for performance
	cacheNodes   []node         // cache node for performance
	cacheNubs    []*MPTProofNub // cache proof nubs to check revive duplicate
}

// VerifyProof verify proof in MPT witness
// 1. calculate hash
// 2. decode trie node
// 3. verify partial merkle proof of the witness
// 4. split to partial witness
func (m *MPTProofCache) VerifyProof() error {
	m.cacheHashes = make([][]byte, len(m.Proof))
	m.cacheNodes = make([]node, len(m.Proof))
	m.cacheHexPath = make([][]byte, len(m.Proof))
	hasher := newHasher(false)
	defer returnHasherToPool(hasher)

	var child []byte
	for i := len(m.Proof) - 1; i >= 0; i-- {
		m.cacheHashes[i] = hasher.hashData(m.Proof[i])
		n, err := decodeNode(m.cacheHashes[i], m.Proof[i])
		if err != nil {
			return err
		}
		m.cacheNodes[i] = n

		switch t := n.(type) {
		case *shortNode:
			m.cacheHexPath[i] = t.Key
			if err := matchHashNodeInShortNode(child, t); err != nil {
				return err
			}
		case *fullNode:
			index, err := matchHashNodeInFullNode(child, t)
			if err != nil {
				return err
			}
			if index >= 0 {
				m.cacheHexPath[i] = []byte{byte(index)}
			}
		case valueNode:
			if child != nil {
				return errors.New("proof wrong child in valueNode")
			}
		default:
			return fmt.Errorf("proof got wrong trie node: %v", t.nodeType())
		}

		child = m.cacheHashes[i]
	}

	// cache proof nubs
	m.cacheNubs = make([]*MPTProofNub, 0, len(m.Proof))
	prefix := m.RootKeyHex
	for i := 0; i < len(m.cacheNodes); i++ {
		if i-1 >= 0 {
			prefix = copyNewSlice(prefix, m.cacheHexPath[i-1])
		}
		// prefix = append(prefix, m.cacheHexPath[i]...)
		n1 := m.cacheNodes[i]
		nub := MPTProofNub{
			n1PrefixKey: prefix,
			n1:          n1,
			n2:          nil,
			n2PrefixKey: nil,
		}

		// check if satisfy partial witness rules,
		// that short node must with its child, may full node or valueNode
		merge, err := mergeNextNode(m.cacheNodes, i)
		if err != nil {
			return err
		}
		if merge {
			i++
			prefix = copyNewSlice(prefix, m.cacheHexPath[i-1])
			nub.n2 = m.cacheNodes[i]
			nub.n2PrefixKey = prefix
		}
		m.cacheNubs = append(m.cacheNubs, &nub)
	}

	return nil
}

func copyNewSlice(s1, s2 []byte) []byte {
	ret := make([]byte, len(s1)+len(s2))
	copy(ret, s1)
	copy(ret[len(s1):], s2)
	return ret
}

func (m *MPTProofCache) CacheNubs() []*MPTProofNub {
	return m.cacheNubs
}

// mergeNextNode check short node must with child in same nub
func mergeNextNode(nodes []node, i int) (bool, error) {
	if i >= len(nodes) {
		return false, errors.New("mergeNextNode input outbound index")
	}

	n1 := nodes[i]
	switch n := n1.(type) {
	case *shortNode:
		need, err := needNextProofNode(n, n.Val)
		if err != nil {
			return false, err
		}
		if need && i+1 >= len(nodes) {
			return false, errors.New("mergeNextNode short node must with its child")
		}
		return need, nil
	case valueNode:
		return false, errors.New("mergeNextNode value node need merge with prev node")
	}

	if i+1 >= len(nodes) {
		return false, nil
	}
	return nodes[i+1].nodeType() == valueNodeType, nil
}

// needNextProofNode check if node need merge next node into a proofNub, because TrieExtendNode must with its child to revive together
func needNextProofNode(parent, origin node) (bool, error) {
	switch n := origin.(type) {
	case *fullNode:
		for i := 0; i < BranchNodeLength-1; i++ {
			need, err := needNextProofNode(n, n.Children[i])
			if err != nil {
				return false, err
			}
			if need {
				return true, nil
			}
		}
		return false, nil
	case *shortNode:
		if parent.nodeType() == shortNodeType {
			return false, errors.New("needNextProofNode cannot short node's child is short node")
		}
		return needNextProofNode(n, n.Val)
	case valueNode:
		return false, nil
	case hashNode:
		if parent.nodeType() == fullNodeType {
			return false, nil
		}
		return true, nil
	default:
		return false, errors.New("needNextProofNode unsupported node")
	}
}

func matchHashNodeInFullNode(child []byte, n *fullNode) (int, error) {
	if child == nil {
		return -1, nil
	}

	for i := 0; i < BranchNodeLength-1; i++ {
		switch v := n.Children[i].(type) {
		case hashNode:
			if bytes.Equal(child, v) {
				return i, nil
			}
		}
	}
	return -1, errors.New("proof cannot find target child in fullNode")
}

func matchHashNodeInShortNode(child []byte, n *shortNode) error {
	if child == nil {
		return nil
	}

	switch v := n.Val.(type) {
	case hashNode:
		if !bytes.Equal(child, v) {
			return errors.New("proof wrong child in shortNode")
		}
	default:
		return errors.New("proof must hashNode when meet shortNode")
	}
	return nil
}
