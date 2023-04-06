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
	crand "crypto/rand"
	"encoding/binary"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	mrand "math/rand"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
)

func init() {
	mrand.Seed(time.Now().Unix())
}

// makeProvers creates Merkle trie provers based on different implementations to
// test all variations.
func makeProvers(trie *Trie) []func(key []byte) *memorydb.Database {
	var provers []func(key []byte) *memorydb.Database

	// Create a direct trie based Merkle prover
	provers = append(provers, func(key []byte) *memorydb.Database {
		proof := memorydb.New()
		trie.Prove(key, 0, proof)
		return proof
	})
	// Create a leaf iterator based Merkle prover
	provers = append(provers, func(key []byte) *memorydb.Database {
		proof := memorydb.New()
		if it := NewIterator(trie.NodeIterator(key)); it.Next() && bytes.Equal(key, it.Key) {
			for _, p := range it.Prove() {
				proof.Put(crypto.Keccak256(p), p)
			}
		}
		return proof
	})
	return provers
}

func TestProof(t *testing.T) {
	trie, vals := randomTrie(500)
	root := trie.Hash()
	for i, prover := range makeProvers(trie) {
		for _, kv := range vals {
			proof := prover(kv.k)
			if proof == nil {
				t.Fatalf("prover %d: missing key %x while constructing proof", i, kv.k)
			}
			val, err := VerifyProof(root, kv.k, proof)
			if err != nil {
				t.Fatalf("prover %d: failed to verify proof for key %x: %v\nraw proof: %x", i, kv.k, err, proof)
			}
			if !bytes.Equal(val, kv.v) {
				t.Fatalf("prover %d: verified value mismatch for key %x: have %x, want %x", i, kv.k, val, kv.v)
			}
		}
	}
}

func TestOneElementProof(t *testing.T) {
	trie := new(Trie)
	updateString(trie, "k", "v")
	for i, prover := range makeProvers(trie) {
		proof := prover([]byte("k"))
		if proof == nil {
			t.Fatalf("prover %d: nil proof", i)
		}
		if proof.Len() != 1 {
			t.Errorf("prover %d: proof should have one element", i)
		}
		val, err := VerifyProof(trie.Hash(), []byte("k"), proof)
		if err != nil {
			t.Fatalf("prover %d: failed to verify proof: %v\nraw proof: %x", i, err, proof)
		}
		if !bytes.Equal(val, []byte("v")) {
			t.Fatalf("prover %d: verified value mismatch: have %x, want 'k'", i, val)
		}
	}
}

func TestBadProof(t *testing.T) {
	trie, vals := randomTrie(800)
	root := trie.Hash()
	for i, prover := range makeProvers(trie) {
		for _, kv := range vals {
			proof := prover(kv.k)
			if proof == nil {
				t.Fatalf("prover %d: nil proof", i)
			}
			it := proof.NewIterator(nil, nil)
			for i, d := 0, mrand.Intn(proof.Len()); i <= d; i++ {
				it.Next()
			}
			key := it.Key()
			val, _ := proof.Get(key)
			proof.Delete(key)
			it.Release()

			mutateByte(val)
			proof.Put(crypto.Keccak256(val), val)

			if _, err := VerifyProof(root, kv.k, proof); err == nil {
				t.Fatalf("prover %d: expected proof to fail for key %x", i, kv.k)
			}
		}
	}
}

// Tests that missing keys can also be proven. The test explicitly uses a single
// entry trie and checks for missing keys both before and after the single entry.
func TestMissingKeyProof(t *testing.T) {
	trie := new(Trie)
	updateString(trie, "k", "v")

	for i, key := range []string{"a", "j", "l", "z"} {
		proof := memorydb.New()
		trie.Prove([]byte(key), 0, proof)

		if proof.Len() != 1 {
			t.Errorf("test %d: proof should have one element", i)
		}
		val, err := VerifyProof(trie.Hash(), []byte(key), proof)
		if err != nil {
			t.Fatalf("test %d: failed to verify proof: %v\nraw proof: %x", i, err, proof)
		}
		if val != nil {
			t.Fatalf("test %d: verified value mismatch: have %x, want nil", i, val)
		}
	}
}

type entrySlice []*kv

func (p entrySlice) Len() int           { return len(p) }
func (p entrySlice) Less(i, j int) bool { return bytes.Compare(p[i].k, p[j].k) < 0 }
func (p entrySlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// TestRangeProof tests normal range proof with both edge proofs
// as the existent proof. The test cases are generated randomly.
func TestRangeProof(t *testing.T) {
	trie, vals := randomTrie(4096)
	var entries entrySlice
	for _, kv := range vals {
		entries = append(entries, kv)
	}
	sort.Sort(entries)
	for i := 0; i < 500; i++ {
		start := mrand.Intn(len(entries))
		end := mrand.Intn(len(entries)-start) + start + 1

		proof := memorydb.New()
		if err := trie.Prove(entries[start].k, 0, proof); err != nil {
			t.Fatalf("Failed to prove the first node %v", err)
		}
		if err := trie.Prove(entries[end-1].k, 0, proof); err != nil {
			t.Fatalf("Failed to prove the last node %v", err)
		}
		var keys [][]byte
		var vals [][]byte
		for i := start; i < end; i++ {
			keys = append(keys, entries[i].k)
			vals = append(vals, entries[i].v)
		}
		_, err := VerifyRangeProof(trie.Hash(), keys[0], keys[len(keys)-1], keys, vals, proof)
		if err != nil {
			t.Fatalf("Case %d(%d->%d) expect no error, got %v", i, start, end-1, err)
		}
	}
}

// TestRangeProof tests normal range proof with two non-existent proofs.
// The test cases are generated randomly.
func TestRangeProofWithNonExistentProof(t *testing.T) {
	trie, vals := randomTrie(4096)
	var entries entrySlice
	for _, kv := range vals {
		entries = append(entries, kv)
	}
	sort.Sort(entries)
	for i := 0; i < 500; i++ {
		start := mrand.Intn(len(entries))
		end := mrand.Intn(len(entries)-start) + start + 1
		proof := memorydb.New()

		// Short circuit if the decreased key is same with the previous key
		first := decreseKey(common.CopyBytes(entries[start].k))
		if start != 0 && bytes.Equal(first, entries[start-1].k) {
			continue
		}
		// Short circuit if the decreased key is underflow
		if bytes.Compare(first, entries[start].k) > 0 {
			continue
		}
		// Short circuit if the increased key is same with the next key
		last := increseKey(common.CopyBytes(entries[end-1].k))
		if end != len(entries) && bytes.Equal(last, entries[end].k) {
			continue
		}
		// Short circuit if the increased key is overflow
		if bytes.Compare(last, entries[end-1].k) < 0 {
			continue
		}
		if err := trie.Prove(first, 0, proof); err != nil {
			t.Fatalf("Failed to prove the first node %v", err)
		}
		if err := trie.Prove(last, 0, proof); err != nil {
			t.Fatalf("Failed to prove the last node %v", err)
		}
		var keys [][]byte
		var vals [][]byte
		for i := start; i < end; i++ {
			keys = append(keys, entries[i].k)
			vals = append(vals, entries[i].v)
		}
		_, err := VerifyRangeProof(trie.Hash(), first, last, keys, vals, proof)
		if err != nil {
			t.Fatalf("Case %d(%d->%d) expect no error, got %v", i, start, end-1, err)
		}
	}
	// Special case, two edge proofs for two edge key.
	proof := memorydb.New()
	first := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000").Bytes()
	last := common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").Bytes()
	if err := trie.Prove(first, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(last, 0, proof); err != nil {
		t.Fatalf("Failed to prove the last node %v", err)
	}
	var k [][]byte
	var v [][]byte
	for i := 0; i < len(entries); i++ {
		k = append(k, entries[i].k)
		v = append(v, entries[i].v)
	}
	_, err := VerifyRangeProof(trie.Hash(), first, last, k, v, proof)
	if err != nil {
		t.Fatal("Failed to verify whole rang with non-existent edges")
	}
}

// TestRangeProofWithInvalidNonExistentProof tests such scenarios:
// - There exists a gap between the first element and the left edge proof
// - There exists a gap between the last element and the right edge proof
func TestRangeProofWithInvalidNonExistentProof(t *testing.T) {
	trie, vals := randomTrie(4096)
	var entries entrySlice
	for _, kv := range vals {
		entries = append(entries, kv)
	}
	sort.Sort(entries)

	// Case 1
	start, end := 100, 200
	first := decreseKey(common.CopyBytes(entries[start].k))

	proof := memorydb.New()
	if err := trie.Prove(first, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(entries[end-1].k, 0, proof); err != nil {
		t.Fatalf("Failed to prove the last node %v", err)
	}
	start = 105 // Gap created
	k := make([][]byte, 0)
	v := make([][]byte, 0)
	for i := start; i < end; i++ {
		k = append(k, entries[i].k)
		v = append(v, entries[i].v)
	}
	_, err := VerifyRangeProof(trie.Hash(), first, k[len(k)-1], k, v, proof)
	if err == nil {
		t.Fatalf("Expected to detect the error, got nil")
	}

	// Case 2
	start, end = 100, 200
	last := increseKey(common.CopyBytes(entries[end-1].k))
	proof = memorydb.New()
	if err := trie.Prove(entries[start].k, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(last, 0, proof); err != nil {
		t.Fatalf("Failed to prove the last node %v", err)
	}
	end = 195 // Capped slice
	k = make([][]byte, 0)
	v = make([][]byte, 0)
	for i := start; i < end; i++ {
		k = append(k, entries[i].k)
		v = append(v, entries[i].v)
	}
	_, err = VerifyRangeProof(trie.Hash(), k[0], last, k, v, proof)
	if err == nil {
		t.Fatalf("Expected to detect the error, got nil")
	}
}

// TestOneElementRangeProof tests the proof with only one
// element. The first edge proof can be existent one or
// non-existent one.
func TestOneElementRangeProof(t *testing.T) {
	trie, vals := randomTrie(4096)
	var entries entrySlice
	for _, kv := range vals {
		entries = append(entries, kv)
	}
	sort.Sort(entries)

	// One element with existent edge proof, both edge proofs
	// point to the SAME key.
	start := 1000
	proof := memorydb.New()
	if err := trie.Prove(entries[start].k, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	_, err := VerifyRangeProof(trie.Hash(), entries[start].k, entries[start].k, [][]byte{entries[start].k}, [][]byte{entries[start].v}, proof)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// One element with left non-existent edge proof
	start = 1000
	first := decreseKey(common.CopyBytes(entries[start].k))
	proof = memorydb.New()
	if err := trie.Prove(first, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(entries[start].k, 0, proof); err != nil {
		t.Fatalf("Failed to prove the last node %v", err)
	}
	_, err = VerifyRangeProof(trie.Hash(), first, entries[start].k, [][]byte{entries[start].k}, [][]byte{entries[start].v}, proof)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// One element with right non-existent edge proof
	start = 1000
	last := increseKey(common.CopyBytes(entries[start].k))
	proof = memorydb.New()
	if err := trie.Prove(entries[start].k, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(last, 0, proof); err != nil {
		t.Fatalf("Failed to prove the last node %v", err)
	}
	_, err = VerifyRangeProof(trie.Hash(), entries[start].k, last, [][]byte{entries[start].k}, [][]byte{entries[start].v}, proof)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// One element with two non-existent edge proofs
	start = 1000
	first, last = decreseKey(common.CopyBytes(entries[start].k)), increseKey(common.CopyBytes(entries[start].k))
	proof = memorydb.New()
	if err := trie.Prove(first, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(last, 0, proof); err != nil {
		t.Fatalf("Failed to prove the last node %v", err)
	}
	_, err = VerifyRangeProof(trie.Hash(), first, last, [][]byte{entries[start].k}, [][]byte{entries[start].v}, proof)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test the mini trie with only a single element.
	tinyTrie := new(Trie)
	entry := &kv{randBytes(32), randBytes(20), false}
	tinyTrie.Update(entry.k, entry.v)

	first = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000").Bytes()
	last = entry.k
	proof = memorydb.New()
	if err := tinyTrie.Prove(first, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	if err := tinyTrie.Prove(last, 0, proof); err != nil {
		t.Fatalf("Failed to prove the last node %v", err)
	}
	_, err = VerifyRangeProof(tinyTrie.Hash(), first, last, [][]byte{entry.k}, [][]byte{entry.v}, proof)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestAllElementsProof tests the range proof with all elements.
// The edge proofs can be nil.
func TestAllElementsProof(t *testing.T) {
	trie, vals := randomTrie(4096)
	var entries entrySlice
	for _, kv := range vals {
		entries = append(entries, kv)
	}
	sort.Sort(entries)

	var k [][]byte
	var v [][]byte
	for i := 0; i < len(entries); i++ {
		k = append(k, entries[i].k)
		v = append(v, entries[i].v)
	}
	_, err := VerifyRangeProof(trie.Hash(), nil, nil, k, v, nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// With edge proofs, it should still work.
	proof := memorydb.New()
	if err := trie.Prove(entries[0].k, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(entries[len(entries)-1].k, 0, proof); err != nil {
		t.Fatalf("Failed to prove the last node %v", err)
	}
	_, err = VerifyRangeProof(trie.Hash(), k[0], k[len(k)-1], k, v, proof)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Even with non-existent edge proofs, it should still work.
	proof = memorydb.New()
	first := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000").Bytes()
	last := common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").Bytes()
	if err := trie.Prove(first, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(last, 0, proof); err != nil {
		t.Fatalf("Failed to prove the last node %v", err)
	}
	_, err = VerifyRangeProof(trie.Hash(), first, last, k, v, proof)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestSingleSideRangeProof tests the range starts from zero.
func TestSingleSideRangeProof(t *testing.T) {
	for i := 0; i < 64; i++ {
		trie := new(Trie)
		var entries entrySlice
		for i := 0; i < 4096; i++ {
			value := &kv{randBytes(32), randBytes(20), false}
			trie.Update(value.k, value.v)
			entries = append(entries, value)
		}
		sort.Sort(entries)

		var cases = []int{0, 1, 50, 100, 1000, 2000, len(entries) - 1}
		for _, pos := range cases {
			proof := memorydb.New()
			if err := trie.Prove(common.Hash{}.Bytes(), 0, proof); err != nil {
				t.Fatalf("Failed to prove the first node %v", err)
			}
			if err := trie.Prove(entries[pos].k, 0, proof); err != nil {
				t.Fatalf("Failed to prove the first node %v", err)
			}
			k := make([][]byte, 0)
			v := make([][]byte, 0)
			for i := 0; i <= pos; i++ {
				k = append(k, entries[i].k)
				v = append(v, entries[i].v)
			}
			_, err := VerifyRangeProof(trie.Hash(), common.Hash{}.Bytes(), k[len(k)-1], k, v, proof)
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
		}
	}
}

// TestReverseSingleSideRangeProof tests the range ends with 0xffff...fff.
func TestReverseSingleSideRangeProof(t *testing.T) {
	for i := 0; i < 64; i++ {
		trie := new(Trie)
		var entries entrySlice
		for i := 0; i < 4096; i++ {
			value := &kv{randBytes(32), randBytes(20), false}
			trie.Update(value.k, value.v)
			entries = append(entries, value)
		}
		sort.Sort(entries)

		var cases = []int{0, 1, 50, 100, 1000, 2000, len(entries) - 1}
		for _, pos := range cases {
			proof := memorydb.New()
			if err := trie.Prove(entries[pos].k, 0, proof); err != nil {
				t.Fatalf("Failed to prove the first node %v", err)
			}
			last := common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
			if err := trie.Prove(last.Bytes(), 0, proof); err != nil {
				t.Fatalf("Failed to prove the last node %v", err)
			}
			k := make([][]byte, 0)
			v := make([][]byte, 0)
			for i := pos; i < len(entries); i++ {
				k = append(k, entries[i].k)
				v = append(v, entries[i].v)
			}
			_, err := VerifyRangeProof(trie.Hash(), k[0], last.Bytes(), k, v, proof)
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
		}
	}
}

// TestBadRangeProof tests a few cases which the proof is wrong.
// The prover is expected to detect the error.
func TestBadRangeProof(t *testing.T) {
	trie, vals := randomTrie(4096)
	var entries entrySlice
	for _, kv := range vals {
		entries = append(entries, kv)
	}
	sort.Sort(entries)

	for i := 0; i < 500; i++ {
		start := mrand.Intn(len(entries))
		end := mrand.Intn(len(entries)-start) + start + 1
		proof := memorydb.New()
		if err := trie.Prove(entries[start].k, 0, proof); err != nil {
			t.Fatalf("Failed to prove the first node %v", err)
		}
		if err := trie.Prove(entries[end-1].k, 0, proof); err != nil {
			t.Fatalf("Failed to prove the last node %v", err)
		}
		var keys [][]byte
		var vals [][]byte
		for i := start; i < end; i++ {
			keys = append(keys, entries[i].k)
			vals = append(vals, entries[i].v)
		}
		var first, last = keys[0], keys[len(keys)-1]
		testcase := mrand.Intn(6)
		var index int
		switch testcase {
		case 0:
			// Modified key
			index = mrand.Intn(end - start)
			keys[index] = randBytes(32) // In theory it can't be same
		case 1:
			// Modified val
			index = mrand.Intn(end - start)
			vals[index] = randBytes(20) // In theory it can't be same
		case 2:
			// Gapped entry slice
			index = mrand.Intn(end - start)
			if (index == 0 && start < 100) || (index == end-start-1 && end <= 100) {
				continue
			}
			keys = append(keys[:index], keys[index+1:]...)
			vals = append(vals[:index], vals[index+1:]...)
		case 3:
			// Out of order
			index1 := mrand.Intn(end - start)
			index2 := mrand.Intn(end - start)
			if index1 == index2 {
				continue
			}
			keys[index1], keys[index2] = keys[index2], keys[index1]
			vals[index1], vals[index2] = vals[index2], vals[index1]
		case 4:
			// Set random key to nil, do nothing
			index = mrand.Intn(end - start)
			keys[index] = nil
		case 5:
			// Set random value to nil, deletion
			index = mrand.Intn(end - start)
			vals[index] = nil
		}
		_, err := VerifyRangeProof(trie.Hash(), first, last, keys, vals, proof)
		if err == nil {
			t.Fatalf("%d Case %d index %d range: (%d->%d) expect error, got nil", i, testcase, index, start, end-1)
		}
	}
}

// TestGappedRangeProof focuses on the small trie with embedded nodes.
// If the gapped node is embedded in the trie, it should be detected too.
func TestGappedRangeProof(t *testing.T) {
	trie := new(Trie)
	var entries []*kv // Sorted entries
	for i := byte(0); i < 10; i++ {
		value := &kv{common.LeftPadBytes([]byte{i}, 32), []byte{i}, false}
		trie.Update(value.k, value.v)
		entries = append(entries, value)
	}
	first, last := 2, 8
	proof := memorydb.New()
	if err := trie.Prove(entries[first].k, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(entries[last-1].k, 0, proof); err != nil {
		t.Fatalf("Failed to prove the last node %v", err)
	}
	var keys [][]byte
	var vals [][]byte
	for i := first; i < last; i++ {
		if i == (first+last)/2 {
			continue
		}
		keys = append(keys, entries[i].k)
		vals = append(vals, entries[i].v)
	}
	_, err := VerifyRangeProof(trie.Hash(), keys[0], keys[len(keys)-1], keys, vals, proof)
	if err == nil {
		t.Fatal("expect error, got nil")
	}
}

// TestSameSideProofs tests the element is not in the range covered by proofs
func TestSameSideProofs(t *testing.T) {
	trie, vals := randomTrie(4096)
	var entries entrySlice
	for _, kv := range vals {
		entries = append(entries, kv)
	}
	sort.Sort(entries)

	pos := 1000
	first := decreseKey(common.CopyBytes(entries[pos].k))
	first = decreseKey(first)
	last := decreseKey(common.CopyBytes(entries[pos].k))

	proof := memorydb.New()
	if err := trie.Prove(first, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(last, 0, proof); err != nil {
		t.Fatalf("Failed to prove the last node %v", err)
	}
	_, err := VerifyRangeProof(trie.Hash(), first, last, [][]byte{entries[pos].k}, [][]byte{entries[pos].v}, proof)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}

	first = increseKey(common.CopyBytes(entries[pos].k))
	last = increseKey(common.CopyBytes(entries[pos].k))
	last = increseKey(last)

	proof = memorydb.New()
	if err := trie.Prove(first, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(last, 0, proof); err != nil {
		t.Fatalf("Failed to prove the last node %v", err)
	}
	_, err = VerifyRangeProof(trie.Hash(), first, last, [][]byte{entries[pos].k}, [][]byte{entries[pos].v}, proof)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestHasRightElement(t *testing.T) {
	trie := new(Trie)
	var entries entrySlice
	for i := 0; i < 4096; i++ {
		value := &kv{randBytes(32), randBytes(20), false}
		trie.Update(value.k, value.v)
		entries = append(entries, value)
	}
	sort.Sort(entries)

	var cases = []struct {
		start   int
		end     int
		hasMore bool
	}{
		{-1, 1, true}, // single element with non-existent left proof
		{0, 1, true},  // single element with existent left proof
		{0, 10, true},
		{50, 100, true},
		{50, len(entries), false},               // No more element expected
		{len(entries) - 1, len(entries), false}, // Single last element with two existent proofs(point to same key)
		{len(entries) - 1, -1, false},           // Single last element with non-existent right proof
		{0, len(entries), false},                // The whole set with existent left proof
		{-1, len(entries), false},               // The whole set with non-existent left proof
		{-1, -1, false},                         // The whole set with non-existent left/right proof
	}
	for _, c := range cases {
		var (
			firstKey []byte
			lastKey  []byte
			start    = c.start
			end      = c.end
			proof    = memorydb.New()
		)
		if c.start == -1 {
			firstKey, start = common.Hash{}.Bytes(), 0
			if err := trie.Prove(firstKey, 0, proof); err != nil {
				t.Fatalf("Failed to prove the first node %v", err)
			}
		} else {
			firstKey = entries[c.start].k
			if err := trie.Prove(entries[c.start].k, 0, proof); err != nil {
				t.Fatalf("Failed to prove the first node %v", err)
			}
		}
		if c.end == -1 {
			lastKey, end = common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").Bytes(), len(entries)
			if err := trie.Prove(lastKey, 0, proof); err != nil {
				t.Fatalf("Failed to prove the first node %v", err)
			}
		} else {
			lastKey = entries[c.end-1].k
			if err := trie.Prove(entries[c.end-1].k, 0, proof); err != nil {
				t.Fatalf("Failed to prove the first node %v", err)
			}
		}
		k := make([][]byte, 0)
		v := make([][]byte, 0)
		for i := start; i < end; i++ {
			k = append(k, entries[i].k)
			v = append(v, entries[i].v)
		}
		hasMore, err := VerifyRangeProof(trie.Hash(), firstKey, lastKey, k, v, proof)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if hasMore != c.hasMore {
			t.Fatalf("Wrong hasMore indicator, want %t, got %t", c.hasMore, hasMore)
		}
	}
}

// TestEmptyRangeProof tests the range proof with "no" element.
// The first edge proof must be a non-existent proof.
func TestEmptyRangeProof(t *testing.T) {
	trie, vals := randomTrie(4096)
	var entries entrySlice
	for _, kv := range vals {
		entries = append(entries, kv)
	}
	sort.Sort(entries)

	var cases = []struct {
		pos int
		err bool
	}{
		{len(entries) - 1, false},
		{500, true},
	}
	for _, c := range cases {
		proof := memorydb.New()
		first := increseKey(common.CopyBytes(entries[c.pos].k))
		if err := trie.Prove(first, 0, proof); err != nil {
			t.Fatalf("Failed to prove the first node %v", err)
		}
		_, err := VerifyRangeProof(trie.Hash(), first, nil, nil, nil, proof)
		if c.err && err == nil {
			t.Fatalf("Expected error, got nil")
		}
		if !c.err && err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
	}
}

// TestBloatedProof tests a malicious proof, where the proof is more or less the
// whole trie. Previously we didn't accept such packets, but the new APIs do, so
// lets leave this test as a bit weird, but present.
func TestBloatedProof(t *testing.T) {
	// Use a small trie
	trie, kvs := nonRandomTrie(100)
	var entries entrySlice
	for _, kv := range kvs {
		entries = append(entries, kv)
	}
	sort.Sort(entries)
	var keys [][]byte
	var vals [][]byte

	proof := memorydb.New()
	// In the 'malicious' case, we add proofs for every single item
	// (but only one key/value pair used as leaf)
	for i, entry := range entries {
		trie.Prove(entry.k, 0, proof)
		if i == 50 {
			keys = append(keys, entry.k)
			vals = append(vals, entry.v)
		}
	}
	// For reference, we use the same function, but _only_ prove the first
	// and last element
	want := memorydb.New()
	trie.Prove(keys[0], 0, want)
	trie.Prove(keys[len(keys)-1], 0, want)

	if _, err := VerifyRangeProof(trie.Hash(), keys[0], keys[len(keys)-1], keys, vals, proof); err != nil {
		t.Fatalf("expected bloated proof to succeed, got %v", err)
	}
}

// TestEmptyValueRangeProof tests normal range proof with both edge proofs
// as the existent proof, but with an extra empty value included, which is a
// noop technically, but practically should be rejected.
func TestEmptyValueRangeProof(t *testing.T) {
	trie, values := randomTrie(512)
	var entries entrySlice
	for _, kv := range values {
		entries = append(entries, kv)
	}
	sort.Sort(entries)

	// Create a new entry with a slightly modified key
	mid := len(entries) / 2
	key := common.CopyBytes(entries[mid-1].k)
	for n := len(key) - 1; n >= 0; n-- {
		if key[n] < 0xff {
			key[n]++
			break
		}
	}
	noop := &kv{key, []byte{}, false}
	entries = append(append(append([]*kv{}, entries[:mid]...), noop), entries[mid:]...)

	start, end := 1, len(entries)-1

	proof := memorydb.New()
	if err := trie.Prove(entries[start].k, 0, proof); err != nil {
		t.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(entries[end-1].k, 0, proof); err != nil {
		t.Fatalf("Failed to prove the last node %v", err)
	}
	var keys [][]byte
	var vals [][]byte
	for i := start; i < end; i++ {
		keys = append(keys, entries[i].k)
		vals = append(vals, entries[i].v)
	}
	_, err := VerifyRangeProof(trie.Hash(), keys[0], keys[len(keys)-1], keys, vals, proof)
	if err == nil {
		t.Fatalf("Expected failure on noop entry")
	}
}

// TestAllElementsEmptyValueRangeProof tests the range proof with all elements,
// but with an extra empty value included, which is a noop technically, but
// practically should be rejected.
func TestAllElementsEmptyValueRangeProof(t *testing.T) {
	trie, values := randomTrie(512)
	var entries entrySlice
	for _, kv := range values {
		entries = append(entries, kv)
	}
	sort.Sort(entries)

	// Create a new entry with a slightly modified key
	mid := len(entries) / 2
	key := common.CopyBytes(entries[mid-1].k)
	for n := len(key) - 1; n >= 0; n-- {
		if key[n] < 0xff {
			key[n]++
			break
		}
	}
	noop := &kv{key, []byte{}, false}
	entries = append(append(append([]*kv{}, entries[:mid]...), noop), entries[mid:]...)

	var keys [][]byte
	var vals [][]byte
	for i := 0; i < len(entries); i++ {
		keys = append(keys, entries[i].k)
		vals = append(vals, entries[i].v)
	}
	_, err := VerifyRangeProof(trie.Hash(), nil, nil, keys, vals, nil)
	if err == nil {
		t.Fatalf("Expected failure on noop entry")
	}
}

// TestStorageProof tests the storage proof generation and verification.
// This test will also test for partial proof generation and verification.
func TestStorageProof(t *testing.T) {
	trie, vals := randomTrie(500)
	for _, kv := range vals {
		prefixKeys := getPrefixKeys(trie, []byte(kv.k))
		for _, prefixKey := range prefixKeys {
			proof := memorydb.New()
			key := kv.k
			err := trie.ProveStorageWitness(key, prefixKey, proof)
			if err != nil {
				t.Fatalf("missing key %x while constructing proof", kv.k)
			}
			val, err := trie.VerifyStorageWitness(key, prefixKey, proof)
			if err != nil {
				t.Fatalf("failed to verify proof for key %x: prefix %x: %v\nraw proof: %x", key, prefixKey, err, proof)
			}
			if val != nil && !bytes.Equal(val, []byte(kv.v)) {
				t.Fatalf("failed to verify proof for key %x: prefix %x: %v\nraw proof: %x", key, prefixKey, err, proof)
			}
		}
	}
}

// TestOneElementStorageProof tests the storage proof generation and verification
// for a trie with only one element.
func TestOneElementStorageProof(t *testing.T) {
	trie := new(Trie)
	updateString(trie, "k", "v")

	proof := memorydb.New()
	key := []byte("k")
	err := trie.ProveStorageWitness(key, nil, proof)
	if err != nil {
		t.Fatalf("missing key %x while constructing proof", key)
	}

	if proof.Len() != 1 {
		t.Errorf("proof should have one element")
	}

	val, err := VerifyProof(trie.Hash(), []byte("k"), proof)
	if err != nil {
		t.Fatalf("failed to verify proof: %v\nraw proof: %x", err, proof)
	}

	if !bytes.Equal(val, []byte("v")) {
		t.Fatalf("verified value mismatch: have %x, want 'v'", val)
	}
}

// TestEmptyStorageProof tests storage verification with empty proof.
// The verifier should nil for both value and error.
func TestEmptyStorageProof(t *testing.T) {
	trie := new(Trie)
	updateString(trie, "k", "v")

	proof := memorydb.New()
	key := []byte("k")

	val, err := trie.VerifyStorageWitness(key, nil, proof)
	if val != nil && err != nil {
		t.Fatalf("expected nil value and error for empty proof")
	}
}

// TestEmptyKeyStorageProof tests the storage proof with empty key.
// The prover is expected to return
func TestEmptyKeyStorageProof(t *testing.T) {
	trie := new(Trie)
	updateString(trie, "k", "v")

	proof := memorydb.New()
	err := trie.ProveStorageWitness([]byte(""), nil, proof)
	if err == nil {
		t.Fatalf("expected error for empty key")
	}
}

// TestEmptyPrefixKeyStorageProof tests the storage proof with empty prefix key,
// which means that all proofs generated are from the root node.
func TestEmptyPrefixKeyStorageProof(t *testing.T) {
	trie, vals := randomTrie(500)
	for _, kv := range vals {
		proof := memorydb.New()
		key := kv.k

		err := trie.ProveStorageWitness(key, nil, proof)
		if err != nil {
			t.Fatalf("missing key %x while constructing proof", key)
		}
		val, err := trie.VerifyStorageWitness(key, nil, proof)
		if err != nil {
			t.Fatalf("failed to verify proof for key %x: %v\nraw proof: %x", key, err, proof)
		}
		if !bytes.Equal(val, kv.v) {
			t.Fatalf("verified value mismatch for key %x: have %x, want %x", key, val, kv.v)
		}
	}
}

// TestBadStorageProof tests a few cases which the proof is wrong.
// The proof is expected to detect the error.
func TestBadStorageProof(t *testing.T) {

	trie, vals := randomTrie(500)
	for _, kv := range vals {
		prefixKeys := getPrefixKeys(trie, []byte(kv.k))
		for _, prefixKey := range prefixKeys {
			proof := memorydb.New()
			key := []byte(kv.k)
			err := trie.ProveStorageWitness(key, prefixKey, proof)
			if err != nil {
				t.Fatalf("missing key %x while constructing proof", key)
			}

			if proof.Len() == 0 {
				continue
			}

			it := proof.NewIterator(nil, nil)
			for i, d := 0, mrand.Intn(proof.Len()); i <= d; i++ {
				it.Next()
			}
			itKey := it.Key()
			itVal, _ := proof.Get(itKey)
			proof.Delete(itKey)
			it.Release()

			mutateByte(itVal)
			proof.Put(crypto.Keccak256(itVal), itVal)

			if val, err := trie.VerifyStorageWitness(key, prefixKey, proof); err == nil && val != nil {
				t.Fatalf("expected proof to fail for key: %x, prefix: %x", key, prefixKey)
			}
		}
	}
}

// TestBadKeyStorageProof tests the storage proof with a bad key.
// The verifier is expected to return nil for both value and error.
func TestBadKeyStorageProof(t *testing.T) {
	trie := new(Trie)
	updateString(trie, "k", "v")

	proof := memorydb.New()
	key := []byte("x")
	trie.ProveStorageWitness(key, nil, proof)

	val, err := trie.VerifyStorageWitness(key, nil, proof)
	if val != nil && err != nil {
		t.Fatalf("expected nil value and error for bad key")
	}
}

// TestBadPrefixKeyStorageProof tests the storage proof with a bad prefix key.
// The verifier is expected to return nil for both value and error.
func TestBadPrefixKeyStorageProof(t *testing.T) {
	trie := new(Trie)
	updateString(trie, "k", "v")

	proof := memorydb.New()
	key := []byte("k")

	prefixKey := keybytesToHex([]byte("x"))

	trie.ProveStorageWitness(key, prefixKey, proof)

	val, err := trie.VerifyStorageWitness(key, prefixKey, proof)
	if val != nil && err != nil {
		t.Fatalf("expected nil value and error for bad prefix key")
	}
}

// TestKeyPrefixKeySame tests the storage proof with the same key and prefix key.
// The proof size should be 0 and the verifier should return nil for both value and error.
func TestKeyPrefixKeySame(t *testing.T) {
	trie := new(Trie)
	updateString(trie, "k", "v")

	proof := memorydb.New()
	key := []byte("k")

	trie.ProveStorageWitness(key, key, proof)
	if proof.Len() != 0 {
		t.Fatalf("expected proof size to be 0 for same key and prefix key")
	}

	val, err := trie.VerifyStorageWitness(key, key, proof)
	if val != nil && err != nil {
		t.Fatalf("expected nil value and error for same key and prefix key")
	}
}

// TestUnexpiredStorageProof tests the storage proof with a trie containing
// both expired and unexpired data. The prover is expected to give valid proof
// for the unexpired data.
func TestUnexpiredStorageProof(t *testing.T) {
	trie := new(Trie)

	expiredData := map[string]string{
		"abcd": "A",
		"abce": "B",
		"abde": "C",
		"abdf": "D",
	}

	unexpiredData := map[string]string{
		"defg": "E",
		"defh": "F",
		"degh": "G",
		"degi": "H",
	}

	// Loop through the data and insert it into the trie
	for k, v := range expiredData {
		updateString(trie, k, v)
	}

	for k, v := range unexpiredData {
		updateString(trie, k, v)
	}

	prefixKey := keybytesToHex([]byte("abcd"))[:2]

	trie.ExpireByPrefix(prefixKey)

	proof := memorydb.New()
	key := []byte("degi")

	trie.ProveStorageWitness(key, nil, proof)
	val, err := trie.VerifyStorageWitness(key, nil, proof)
	if err != nil {
		t.Fatalf("failed to verify proof: %v\nraw proof: %x", err, proof)
	}
	if !bytes.Equal(val, []byte("H")) {
		t.Fatalf("verified value mismatch: have %x, want %v", val, "H")
	}
}

// mutateByte changes one byte in b.
func mutateByte(b []byte) {
	for r := mrand.Intn(len(b)); ; {
		new := byte(mrand.Intn(255))
		if new != b[r] {
			b[r] = new
			break
		}
	}
}

func increseKey(key []byte) []byte {
	for i := len(key) - 1; i >= 0; i-- {
		key[i]++
		if key[i] != 0x0 {
			break
		}
	}
	return key
}

func decreseKey(key []byte) []byte {
	for i := len(key) - 1; i >= 0; i-- {
		key[i]--
		if key[i] != 0xff {
			break
		}
	}
	return key
}

func BenchmarkProve(b *testing.B) {
	trie, vals := randomTrie(100)
	var keys []string
	for k := range vals {
		keys = append(keys, k)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kv := vals[keys[i%len(keys)]]
		proofs := memorydb.New()
		if trie.Prove(kv.k, 0, proofs); proofs.Len() == 0 {
			b.Fatalf("zero length proof for %x", kv.k)
		}
	}
}

func BenchmarkVerifyProof(b *testing.B) {
	trie, vals := randomTrie(100)
	root := trie.Hash()
	var keys []string
	var proofs []*memorydb.Database
	for k := range vals {
		keys = append(keys, k)
		proof := memorydb.New()
		trie.Prove([]byte(k), 0, proof)
		proofs = append(proofs, proof)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		im := i % len(keys)
		if _, err := VerifyProof(root, []byte(keys[im]), proofs[im]); err != nil {
			b.Fatalf("key %x: %v", keys[im], err)
		}
	}
}

func BenchmarkVerifyRangeProof10(b *testing.B)   { benchmarkVerifyRangeProof(b, 10) }
func BenchmarkVerifyRangeProof100(b *testing.B)  { benchmarkVerifyRangeProof(b, 100) }
func BenchmarkVerifyRangeProof1000(b *testing.B) { benchmarkVerifyRangeProof(b, 1000) }
func BenchmarkVerifyRangeProof5000(b *testing.B) { benchmarkVerifyRangeProof(b, 5000) }

func benchmarkVerifyRangeProof(b *testing.B, size int) {
	trie, vals := randomTrie(8192)
	var entries entrySlice
	for _, kv := range vals {
		entries = append(entries, kv)
	}
	sort.Sort(entries)

	start := 2
	end := start + size
	proof := memorydb.New()
	if err := trie.Prove(entries[start].k, 0, proof); err != nil {
		b.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(entries[end-1].k, 0, proof); err != nil {
		b.Fatalf("Failed to prove the last node %v", err)
	}
	var keys [][]byte
	var values [][]byte
	for i := start; i < end; i++ {
		keys = append(keys, entries[i].k)
		values = append(values, entries[i].v)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := VerifyRangeProof(trie.Hash(), keys[0], keys[len(keys)-1], keys, values, proof)
		if err != nil {
			b.Fatalf("Case %d(%d->%d) expect no error, got %v", i, start, end-1, err)
		}
	}
}

func BenchmarkVerifyRangeNoProof10(b *testing.B)   { benchmarkVerifyRangeNoProof(b, 100) }
func BenchmarkVerifyRangeNoProof500(b *testing.B)  { benchmarkVerifyRangeNoProof(b, 500) }
func BenchmarkVerifyRangeNoProof1000(b *testing.B) { benchmarkVerifyRangeNoProof(b, 1000) }

func benchmarkVerifyRangeNoProof(b *testing.B, size int) {
	trie, vals := randomTrie(size)
	var entries entrySlice
	for _, kv := range vals {
		entries = append(entries, kv)
	}
	sort.Sort(entries)

	var keys [][]byte
	var values [][]byte
	for _, entry := range entries {
		keys = append(keys, entry.k)
		values = append(values, entry.v)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := VerifyRangeProof(trie.Hash(), keys[0], keys[len(keys)-1], keys, values, nil)
		if err != nil {
			b.Fatalf("Expected no error, got %v", err)
		}
	}
}

func randomTrie(n int) (*Trie, map[string]*kv) {
	trie := new(Trie)
	vals := make(map[string]*kv)
	for i := byte(0); i < 100; i++ {
		value := &kv{common.LeftPadBytes([]byte{i}, 32), []byte{i}, false}
		value2 := &kv{common.LeftPadBytes([]byte{i + 10}, 32), []byte{i}, false}
		trie.Update(value.k, value.v)
		trie.Update(value2.k, value2.v)
		vals[string(value.k)] = value
		vals[string(value2.k)] = value2
	}
	for i := 0; i < n; i++ {
		value := &kv{randBytes(32), randBytes(20), false}
		trie.Update(value.k, value.v)
		vals[string(value.k)] = value
	}
	return trie, vals
}

func randBytes(n int) []byte {
	r := make([]byte, n)
	crand.Read(r)
	return r
}

func nonRandomTrie(n int) (*Trie, map[string]*kv) {
	trie := new(Trie)
	vals := make(map[string]*kv)
	max := uint64(0xffffffffffffffff)
	for i := uint64(0); i < uint64(n); i++ {
		value := make([]byte, 32)
		key := make([]byte, 32)
		binary.LittleEndian.PutUint64(key, i)
		binary.LittleEndian.PutUint64(value, i-max)
		//value := &kv{common.LeftPadBytes([]byte{i}, 32), []byte{i}, false}
		elem := &kv{key, value, false}
		trie.Update(elem.k, elem.v)
		vals[string(elem.k)] = elem
	}
	return trie, vals
}

func TestRangeProofKeysWithSharedPrefix(t *testing.T) {
	keys := [][]byte{
		common.Hex2Bytes("aa10000000000000000000000000000000000000000000000000000000000000"),
		common.Hex2Bytes("aa20000000000000000000000000000000000000000000000000000000000000"),
	}
	vals := [][]byte{
		common.Hex2Bytes("02"),
		common.Hex2Bytes("03"),
	}
	trie := new(Trie)
	for i, key := range keys {
		trie.Update(key, vals[i])
	}
	root := trie.Hash()
	proof := memorydb.New()
	start := common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000")
	end := common.Hex2Bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err := trie.Prove(start, 0, proof); err != nil {
		t.Fatalf("failed to prove start: %v", err)
	}
	if err := trie.Prove(end, 0, proof); err != nil {
		t.Fatalf("failed to prove end: %v", err)
	}

	more, err := VerifyRangeProof(root, start, end, keys, vals, proof)
	if err != nil {
		t.Fatalf("failed to verify range proof: %v", err)
	}
	if more != false {
		t.Error("expected more to be false")
	}
}

func getPrefixKeys(t *Trie, key []byte) [][]byte {
	var prefixKeys [][]byte
	key = keybytesToHex(key)
	tn := t.root
	for len(key) > 0 && tn != nil {
		switch n := tn.(type) {
		case *shortNode:
			if len(key) < len(n.Key) || !bytes.Equal(n.Key, key[:len(n.Key)]) {
				// The trie doesn't contain the key.
				tn = nil
			} else {
				tn = n.Val
				// Check if there is a previous key in prefixKeys
				if len(prefixKeys) == 0 {
					prefixKeys = append(prefixKeys, n.Key)
				} else {
					prefixKeys = append(prefixKeys, append(prefixKeys[len(prefixKeys)-1], n.Key...))
				}
				key = key[len(n.Key):]
			}
		case *fullNode:
			tn = n.Children[key[0]]
			if len(prefixKeys) == 0 {
				prefixKeys = append(prefixKeys, key[:1])
			} else {
				prefixKeys = append(prefixKeys, append(prefixKeys[len(prefixKeys)-1], key[:1]...))
			}
			key = key[1:]
		case hashNode:
			var err error
			tn, err = t.resolveHash(n, nil)
			if err != nil {
				return nil
			}
		default:
			return nil
		}
	}

	return prefixKeys
}

func TestMPTProofCache_VerifyProof_normalCase(t *testing.T) {
	cache := makeMPTProofCache(nil, []string{
		"0xf90211a03697534056039e03300557bd69fe16e18ce4a6ccd5522db4dfa97dfe1fad3d3aa0b1bf1f230b98b9034738d599177ae817c08143b9395a47f300636b0dd2fb3c5ea0aa04a4966751d4c50063fe13a96a6c7924f665819733f556849b5eb9fa1d6839a0e162e080d1c12c59dc984fb2246d8ad61209264bee40d3fdd07c4ea4ff411b6aa0e5c3f2dde71bf303423f34674748567dcdf8379129653b8213f698468738d492a068a3e3059b6e7115a055a7874f81c5a1e84ddc1967527973f8c78cd86a1c9f8fa0d734bd63b7be8e8471091b792f5bbcbc7b0ce582f6d985b7a15a3c0155242c56a00143c06f57a65c8485dbae750aa51df5dff1bf7bdf28060129a20de9e51364eda07b416f79b3f4e39d0159efff351009d44002d9e83530fb5a5778eb55f5f4432ca036706b52196fa0b73feb2e7ff8f1379c7176d427dd44ad63c7b65e66693904a1a0fd6c8b815e2769ce379a20eaccdba1f145fb11f77c280553f15ee4f1ee135375a02f5233009f082177e5ed2bfa6e180bf1a7310e6bc3c079cb85a4ac6fee4ae379a03f07f1bb33fa26ebd772fa874914dc7a08581095e5159fdcf9221be6cbeb6648a097557eec1ac08c3bfe45ce8e34cd329164a33928ac83fef1009656536ef6907fa028196bfb31aa7f14a0a8000b00b0aa5d09450c32d537e45eebee70b14313ff1ca0126ce265ca7bbb0e0b01f068d1edef1544cbeb2f048c99829713c18d7abc049a80",
		"0xf90211a01f7c019858f447dbff8ed8e4329e88600bab8f17fec9594c664e25acc95da3dba00916866833439bc250b5e08edc2b7c041634ca3b33a013f79eb299a3e33a056fa0a8fae921061f3bc81154b5d2c149d3860a3cdef00d02173ee3b5837de6b26f56a097583621a54e74994619a97cf82f823005a35ad1bf4795047726619eccd11ad4a0be39789c4abdb2a185cce40f2c77575eee2a1eab38d3168395560da15307614aa0c46a7fcea5501656d70508178f0731460edcce1c01e32ed08c1468f2593db277a0460f030038b09b8461d834ded79d77fd3ed25c4e248775752bf1c830a530ef2ba03d887abec623c6b4d93be75d1608dcacb291bf30406fbbc944a94aa4203fb1eba0475eeb07d471044af74313093cfbb0201e17a405d7af13a7ae6b245e18915515a0ea794035230f90e14f4f601d0e9f04217ed02710df363417bc3dd7dda5a84608a08aa9f0c44e5a9e359b65d4f0e40937662f07af10642a626e19ca7bc56c329706a05677c9b342c1cbcfd491cd491800d44423d1bdc08ab00eb59376a7118f7c4e23a0b761f22d67328e6c90caf8be65affb701b045f4f1f581472fc5f724e0c61328da0b6727240643009e59bba78249918a83ca8faeaf1d5b47fe0b41c356e8ae300dda0d7cbeb12faf439126bdb86f94b6262c3a70e88e4d8a47b49735f0b9d632a5df8a0428fe930556ce5ea94bcc4d092fe0f05a2a9b360175857711729ab3a7092a81780",
		"0xf90211a0a81ff74945250ba9925753e379aa8815a3fe77926aad2d02db4d78a3da7ecb48a0e795c64d2b738b34ebb77a3307df800c9f1fe324b442cd71ffa5fd268ec12ffca020a5f968a1c8292d08135cb451daed999a44eb0cdd04526a89c38e753398c50ca0cc7165f6b984f2f2569d101d70f72af94eb79b18c126895da2d3cf557b5aca51a00a10f4dc5851e71f195cca5bd7a2a62a6c3ca03d95e91c7dc55e55f4cb726903a09ecaaf877b18a55ca4001fe46cc10389c94104abc2994cdfe5843f28814b119ca099f59b2b52ee9d9b44ab7123a86775dcfe6c50301dd7cf9c6fc6ea968c1d2a01a0fccda5c1489dd3268fcf2471f6a372fc3afe5eebecc0ba9fc3c023d85da26aeda0d730ea7aabdad2e5451e826726e53c86e6e805e46220bc7edd80bf3f7e467f96a074f3d767a84557aa9559b08b2d1f93d8205827c042d1ac616b8cf37e22de2beca03ca1fe479ea1e64c3bfeae9c603ef4f55c270de0bb4c79d045f67d3481ca2852a0bdcbc3d154db40b5faa1f6875f46d485b96bdfffb4513da631f9b302768faae7a096923f4f559c7b7f912587292cc865aba5934e9e75c9aa88f20de73e928c6c51a0f52ca9710977327dd407ba9d9f00b0075d7e312ee19686f1b53579585ff50132a076adb4cf98f9af261d1b2a147b9b2cbace1647eab537ca1a55e8d40d35775b74a0723fa2f72d6a983939bc9bf9ee22e05fc142437726450e5707c60155bc34ec0580",
		"0xf90211a039a64fd9b31f3ea3bf9a991ca828eadb67cf9ae0ebbcdd195d297454699580e8a0c95d85a63beb9a02b56d032116d86fdf9a64065dd5d44e33acef674ae3ceb6f9a0d83ef07a99302abccdce1289d353a20494713f45d8edbd3c2e87f08788a878d9a063a19aee41fec40a98edcf4d60c759c509b512bfc5d9feae7de50c8c2d00eee7a029ce5c8c1ac9939cbf481274b8e6f5f24a430136dc5aab7deb489a9ce7db5a95a03b45c53d2e4f54e49a53eb298aee828f4803581ee60ca52940533b77c3e3fadfa082b8084dfc0337a49fd5d53ce107fa0bdcdf25ac7bbac017d7ac250b77c8764da0d4dab90004fd3bb36b2fa5f6e914a7c90820d119e5ba3ba8439270c6cfbd0a18a0bd9286c9248ae8a953d00aa9906f06b6f0364d0bb9fb615de04c9f8d5b5fd346a00955eccaa41a17fafb0ed66272b5183b3a30a973af7a43e0f25f0b640fd5df0ca0a7ba773602ace05991211770fc5555dd9c55e2518bcb005d1db022584a89132da0450b066588b44701992ab4a926d5dd185dd465abf1e51a3f60ab4a9f924cf85aa05eda0687636512339d0db99eade61c0d44358bb8027185296ad59b4cedd2935aa0cd18604dee296e5443b598e470a04efde04fbb0213c0fda8cc3af20dae2a1c34a01c0474c1bf15e4732d1c22a1303573c7ec8643f711354e853ab26038b2eebe25a081a0b2d329a9519375f71384a7130faafc3a1379db59bfb7db7135c9d27d9cc080",
		"0xf901f1a0e14d9caa85464966f0371f427250e7bf2d86f6d41535b08ea79044391d6f0fe7a08bea233c92e4c1d05bd03d62cd93974cc29f6df54e6fa2574bf8dfb3af936a85a0dd4f4af9ab72d1bbbf59c286a731614f48bf3cdcef572cd819426fc2a30ae5d9a058465ea8e97b2f3a873646f9504aff111ab967abaea8ebb2fe91bf058ea162f3a06466c41eb770bae5c07c26cd692540e7f9af70fee2bc164e12f29083ebd2cca1a0fe0925da033ffb967ca1e1d6505c2ca740553916c3b9a205131d719b7921fb00a0973ecee958d1305f1b6f8159a9732e47f5fbd4121f60254ea44a8f028308150780a0f81717c7f8702ed39d89a34fc86827aab31db26b22d22ee399667e4a44081c95a0e276ec24ee74ee61bdbe92e8afa57813d59f26e0ad34f24d71f0627719f8a11ea00a8ec2f6922480890f9e67c62c1654dcccf1710a01a378f614e02a3785d42d7ea08c43cc0c6c690dd87cf42691e9ead799c5ddbcfc9458ebd054a46acecedbe9f7a0d3727ed077c60ed6ff1d9d5d20fdf2912a513942d0efee9ec2d97d33ab9b7f56a03f293b0c0f25b9aa2735c4e42b132008d8af2ecfaaefdc940dc94cf312f5a1dda04860bc5f19829bb277554927c5b6dbc0af93025aca49aed3be020a3080996a26a0e47475bf4f62364d8a0dd87f2c21d0b64ef4d9aaf5fc46d9b1e3af5b83f56d4580",
		"0xf89180a0dd3524693059f48ce47c5dd82d0462953a5141c7abc5a63981637b71e0100bcf80a033ca98826ea65c1c4be16e1df12e78142d992bf1fc0189401632ceff3fcbbe7880a0e5daf803b0890d164e287fa43b51332286cddeb9b62280426037fc02dc2b4d5f8080a0bfa907c2e30720a07347d23cfa573dec8c9b3afa51a4a0e0783a481da0fcb1b38080808080808080",
		"0xe79e208246cec5810061f4ff7efe1dcd6cb407d59abc3478830df04484584c868786d647b234389e",
	})

	err := cache.VerifyProof()
	assert.NoError(t, err)
	assert.Equal(t, common.Hex2Bytes("3310913fe74cfb66dbde8fe8557b48e8e65617a17c2375a581c32d49f812cde4"), cache.cacheHashes[0])
	key := common.Hex2Bytes("95eea00c49d14a895954837cd876ffa8cfad96cbaacc40fc31d6df2c902528a8")
	hash := make([]byte, common.HashLength)
	h := newHasher(false)
	h.sha.Reset()
	h.sha.Write(key)
	h.sha.Read(hash)
	assert.Equal(t, hash, hexToKeybytes(cache.cacheNubs[6].RootHexKey))
}

func makeMPTProofCache(key []byte, proofs []string) MPTProofCache {

	proof := make([][]byte, len(proofs))
	for i := range proofs {
		proof[i] = common.Hex2Bytes(strings.TrimPrefix(proofs[i], "0x"))
	}
	return MPTProofCache{
		MPTProof: types.MPTProof{
			RootKey: key,
			Proof:   proof,
		},
	}
}
