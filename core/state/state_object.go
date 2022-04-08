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

package state

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/rlp"
)

var emptyCodeHash = crypto.Keccak256(nil)

type Code []byte

func (c Code) String() string {
	return string(c) //strings.Join(Disassemble(c), " ")
}

type Storage interface {
	String() string
	GetValue(hash common.Hash) (common.Hash, bool)
	StoreValue(hash common.Hash, value common.Hash)
	Length() (length int)
	Copy() Storage
	Range(func(key, value interface{}) bool)
}

type StorageMap map[common.Hash]common.Hash

func (s StorageMap) String() (str string) {
	for key, value := range s {
		str += fmt.Sprintf("%X : %X\n", key, value)
	}

	return
}

func (s StorageMap) Copy() Storage {
	cpy := make(StorageMap)
	for key, value := range s {
		cpy[key] = value
	}

	return cpy
}

func (s StorageMap) GetValue(hash common.Hash) (common.Hash, bool) {
	value, ok := s[hash]
	return value, ok
}

func (s StorageMap) StoreValue(hash common.Hash, value common.Hash) {
	s[hash] = value
}

func (s StorageMap) Length() int {
	return len(s)
}

func (s StorageMap) Range(f func(hash, value interface{}) bool) {
	for k, v := range s {
		result := f(k, v)
		if !result {
			return
		}
	}
}

type StorageSyncMap struct {
	sync.Map
}

func (s *StorageSyncMap) String() (str string) {
	s.Range(func(key, value interface{}) bool {
		str += fmt.Sprintf("%X : %X\n", key, value)
		return true
	})

	return
}

func (s *StorageSyncMap) GetValue(hash common.Hash) (common.Hash, bool) {
	value, ok := s.Load(hash)
	if !ok {
		return common.Hash{}, ok
	}

	return value.(common.Hash), ok
}

func (s *StorageSyncMap) StoreValue(hash common.Hash, value common.Hash) {
	s.Store(hash, value)
}

func (s *StorageSyncMap) Length() (length int) {
	s.Range(func(key, value interface{}) bool {
		length++
		return true
	})
	return length
}

func (s *StorageSyncMap) Copy() Storage {
	cpy := StorageSyncMap{}
	s.Range(func(key, value interface{}) bool {
		cpy.Store(key, value)
		return true
	})

	return &cpy
}

func newStorage(isParallel bool) Storage {
	if isParallel {
		return &StorageSyncMap{}
	}
	return make(StorageMap)
}

// StateObject represents an Ethereum account which is being modified.
//
// The usage pattern is as follows:
// First you need to obtain a state object.
// Account values can be accessed and modified through the object.
// Finally, call CommitTrie to write the modified storage trie into a database.
type StateObject struct {
	address  common.Address
	addrHash common.Hash // hash of ethereum address of the account
	data     Account
	db       *StateDB

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be returned
	// by StateDB.Commit.
	dbErr error

	// Write caches.
	trie Trie // storage trie, which becomes non-nil on first access
	code Code // contract bytecode, which gets set when code is loaded

	isParallel     bool    // isParallel indicates this state object is used in parallel mode
	originStorage  Storage // Storage cache of original entries to dedup rewrites, reset for every transaction
	pendingStorage Storage // Storage entries that need to be flushed to disk, at the end of an entire block
	dirtyStorage   Storage // Storage entries that have been modified in the current transaction execution
	fakeStorage    Storage // Fake storage which constructed by caller for debugging purpose.

	// Cache flags.
	// When an object is marked suicided it will be delete from the trie
	// during the "update" phase of the state transition.
	dirtyCode bool // true if the code was updated
	suicided  bool
	deleted   bool

	//encode
	encodeData []byte
}

// empty returns whether the account is considered empty.
func (s *StateObject) empty() bool {
	return s.data.Nonce == 0 && s.data.Balance.Sign() == 0 && bytes.Equal(s.data.CodeHash, emptyCodeHash)
}

// Account is the Ethereum consensus representation of accounts.
// These objects are stored in the main account trie.
type Account struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash // merkle root of the storage trie
	CodeHash []byte
}

// newObject creates a state object.
func newObject(db *StateDB, isParallel bool, address common.Address, data Account) *StateObject {
	if data.Balance == nil {
		data.Balance = new(big.Int)
	}
	if data.CodeHash == nil {
		data.CodeHash = emptyCodeHash
	}
	if data.Root == (common.Hash{}) {
		data.Root = emptyRoot
	}
	return &StateObject{
		db:             db,
		address:        address,
		addrHash:       crypto.Keccak256Hash(address[:]),
		data:           data,
		isParallel:     isParallel,
		originStorage:  newStorage(isParallel),
		dirtyStorage:   newStorage(isParallel),
		pendingStorage: newStorage(isParallel),
	}
}

// EncodeRLP implements rlp.Encoder.
func (s *StateObject) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, s.data)
}

// setError remembers the first non-nil error it is called with.
func (s *StateObject) setError(err error) {
	if s.dbErr == nil {
		s.dbErr = err
	}
}

func (s *StateObject) markSuicided() {
	s.suicided = true
}

func (s *StateObject) touch() {
	s.db.journal.append(touchChange{
		account: &s.address,
	})
	if s.address == ripemd {
		// Explicitly put it in the dirty-cache, which is otherwise generated from
		// flattened journals.
		s.db.journal.dirty(s.address)
	}
}

func (s *StateObject) getTrie(db Database) Trie {
	if s.trie == nil {
		// Try fetching from prefetcher first
		// We don't prefetch empty tries
		if s.data.Root != emptyRoot && s.db.prefetcher != nil {
			// When the miner is creating the pending state, there is no
			// prefetcher
			s.trie = s.db.prefetcher.trie(s.data.Root)
		}
		if s.trie == nil {
			var err error
			s.trie, err = db.OpenStorageTrie(s.addrHash, s.data.Root)
			if err != nil {
				s.trie, _ = db.OpenStorageTrie(s.addrHash, common.Hash{})
				s.setError(fmt.Errorf("can't create storage trie: %v", err))
			}
		}
	}
	return s.trie
}

// GetState retrieves a value from the account storage trie.
func (s *StateObject) GetState(db Database, key common.Hash) common.Hash {
	// If the fake storage is set, only lookup the state here(in the debugging mode)
	if s.fakeStorage != nil {
		fakeValue, _ := s.fakeStorage.GetValue(key)
		return fakeValue
	}
	// If we have a dirty value for this state entry, return it
	value, dirty := s.dirtyStorage.GetValue(key)
	if dirty {
		return value
	}
	// Otherwise return the entry's original value
	return s.GetCommittedState(db, key)
}

// GetCommittedState retrieves a value from the committed account storage trie.
func (s *StateObject) GetCommittedState(db Database, key common.Hash) common.Hash {
	// If the fake storage is set, only lookup the state here(in the debugging mode)
	if s.fakeStorage != nil {
		fakeValue, _ := s.fakeStorage.GetValue(key)
		return fakeValue
	}
	// If we have a pending write or clean cached, return that
	if value, pending := s.pendingStorage.GetValue(key); pending {
		return value
	}
	if value, cached := s.originStorage.GetValue(key); cached {
		return value
	}
	// If no live objects are available, attempt to use snapshots
	var (
		enc   []byte
		err   error
		meter *time.Duration
	)
	readStart := time.Now()
	if metrics.EnabledExpensive {
		// If the snap is 'under construction', the first lookup may fail. If that
		// happens, we don't want to double-count the time elapsed. Thus this
		// dance with the metering.
		defer func() {
			if meter != nil {
				*meter += time.Since(readStart)
			}
		}()
	}
	if s.db.snap != nil {
		if metrics.EnabledExpensive {
			meter = &s.db.SnapshotStorageReads
		}
		// If the object was destructed in *this* block (and potentially resurrected),
		// the storage has been cleared out, and we should *not* consult the previous
		// snapshot about any storage values. The only possible alternatives are:
		//   1) resurrect happened, and new slot values were set -- those should
		//      have been handles via pendingStorage above.
		//   2) we don't have new values, and can deliver empty response back
		if _, destructed := s.db.snapDestructs[s.address]; destructed {
			return common.Hash{}
		}
		enc, err = s.db.snap.Storage(s.addrHash, crypto.Keccak256Hash(key.Bytes()))
	}
	// If snapshot unavailable or reading from it failed, load from the database
	if s.db.snap == nil || err != nil {
		if meter != nil {
			// If we already spent time checking the snapshot, account for it
			// and reset the readStart
			*meter += time.Since(readStart)
			readStart = time.Now()
		}
		if metrics.EnabledExpensive {
			meter = &s.db.StorageReads
		}
		if enc, err = s.getTrie(db).TryGet(key.Bytes()); err != nil {
			s.setError(err)
			return common.Hash{}
		}
	}
	var value common.Hash
	if len(enc) > 0 {
		_, content, _, err := rlp.Split(enc)
		if err != nil {
			s.setError(err)
		}
		value.SetBytes(content)
	}
	s.originStorage.StoreValue(key, value)
	return value
}

// SetState updates a value in account storage.
func (s *StateObject) SetState(db Database, key, value common.Hash) {
	// If the fake storage is set, put the temporary state update here.
	if s.fakeStorage != nil {
		s.fakeStorage.StoreValue(key, value)
		return
	}
	// If the new value is the same as old, don't set
	prev := s.GetState(db, key)
	if prev == value {
		return
	}
	// New value is different, update and journal the change
	s.db.journal.append(storageChange{
		account:  &s.address,
		key:      key,
		prevalue: prev,
	})
	s.setState(key, value)
}

// SetStorage replaces the entire state storage with the given one.
//
// After this function is called, all original state will be ignored and state
// lookup only happens in the fake state storage.
//
// Note this function should only be used for debugging purpose.
func (s *StateObject) SetStorage(storage map[common.Hash]common.Hash) {
	// Allocate fake storage if it's nil.
	if s.fakeStorage == nil {
		s.fakeStorage = newStorage(s.isParallel)
	}
	for key, value := range storage {
		s.fakeStorage.StoreValue(key, value)
	}
	// Don't bother journal since this function should only be used for
	// debugging and the `fake` storage won't be committed to database.
}

func (s *StateObject) setState(key, value common.Hash) {
	s.dirtyStorage.StoreValue(key, value)
}

// finalise moves all dirty storage slots into the pending area to be hashed or
// committed later. It is invoked at the end of every transaction.
func (s *StateObject) finalise(prefetch bool) {
	slotsToPrefetch := make([][]byte, 0, s.dirtyStorage.Length())
	s.dirtyStorage.Range(func(key, value interface{}) bool {
		s.pendingStorage.StoreValue(key.(common.Hash), value.(common.Hash))

		originalValue, _ := s.originStorage.GetValue(key.(common.Hash))
		if value.(common.Hash) != originalValue {
			originalKey := key.(common.Hash)
			slotsToPrefetch = append(slotsToPrefetch, common.CopyBytes(originalKey[:])) // Copy needed for closure
		}
		return true
	})

	if s.db.prefetcher != nil && prefetch && len(slotsToPrefetch) > 0 && s.data.Root != emptyRoot {
		s.db.prefetcher.prefetch(s.data.Root, slotsToPrefetch, s.addrHash)
	}
	if s.dirtyStorage.Length() > 0 {
		s.dirtyStorage = newStorage(s.isParallel)
	}
}

// updateTrie writes cached storage modifications into the object's storage trie.
// It will return nil if the trie has not been loaded and no changes have been made
func (s *StateObject) updateTrie(db Database) Trie {
	// Make sure all dirty slots are finalized into the pending storage area
	s.finalise(false) // Don't prefetch any more, pull directly if need be
	if s.pendingStorage.Length() == 0 {
		return s.trie
	}
	// Track the amount of time wasted on updating the storage trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) {
			s.db.MetricsMux.Lock()
			s.db.StorageUpdates += time.Since(start)
			s.db.MetricsMux.Unlock()
		}(time.Now())
	}
	// The snapshot storage map for the object
	var storage map[string][]byte
	// Insert all the pending updates into the trie
	tr := s.getTrie(db)

	usedStorage := make([][]byte, 0, s.pendingStorage.Length())

	s.pendingStorage.Range(func(k, v interface{}) bool {
		key := k.(common.Hash)
		value := v.(common.Hash)

		// Skip noop changes, persist actual changes
		originalValue, _ := s.originStorage.GetValue(k.(common.Hash))
		if v.(common.Hash) == originalValue {
			return true
		}

		s.originStorage.StoreValue(k.(common.Hash), v.(common.Hash))

		var vs []byte
		if (value == common.Hash{}) {
			s.setError(tr.TryDelete(key[:]))
		} else {
			// Encoding []byte cannot fail, ok to ignore the error.
			vs, _ = rlp.EncodeToBytes(common.TrimLeftZeroes(value[:]))
			s.setError(tr.TryUpdate(key[:], vs))
		}
		// If state snapshotting is active, cache the data til commit
		if s.db.snap != nil {
			s.db.snapMux.Lock()
			if storage == nil {
				// Retrieve the old storage map, if available, create a new one otherwise
				if storage = s.db.snapStorage[s.address]; storage == nil {
					storage = make(map[string][]byte)
					s.db.snapStorage[s.address] = storage
				}
			}
			storage[string(key[:])] = vs // v will be nil if value is 0x00
			s.db.snapMux.Unlock()
		}
		usedStorage = append(usedStorage, common.CopyBytes(key[:])) // Copy needed for closure
		return true
	})

	if s.db.prefetcher != nil {
		s.db.prefetcher.used(s.data.Root, usedStorage)
	}
	if s.pendingStorage.Length() > 0 {
		s.pendingStorage = newStorage(s.isParallel)
	}
	return tr
}

// UpdateRoot sets the trie root to the current root hash of
func (s *StateObject) updateRoot(db Database) {
	// If nothing changed, don't bother with hashing anything
	if s.updateTrie(db) == nil {
		return
	}
	// Track the amount of time wasted on hashing the storage trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) {
			s.db.MetricsMux.Lock()
			s.db.StorageHashes += time.Since(start)
			s.db.MetricsMux.Unlock()
		}(time.Now())
	}
	s.data.Root = s.trie.Hash()
}

// CommitTrie the storage trie of the object to db.
// This updates the trie root.
func (s *StateObject) CommitTrie(db Database) error {
	// If nothing changed, don't bother with hashing anything
	if s.updateTrie(db) == nil {
		if s.trie != nil && s.data.Root != emptyRoot {
			db.CacheStorage(s.addrHash, s.data.Root, s.trie)
		}
		return nil
	}
	if s.dbErr != nil {
		return s.dbErr
	}
	// Track the amount of time wasted on committing the storage trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.db.StorageCommits += time.Since(start) }(time.Now())
	}
	root, err := s.trie.Commit(nil)
	if err == nil {
		s.data.Root = root
	}
	if s.data.Root != emptyRoot {
		db.CacheStorage(s.addrHash, s.data.Root, s.trie)
	}
	return err
}

// AddBalance adds amount to s's balance.
// It is used to add funds to the destination account of a transfer.
func (s *StateObject) AddBalance(amount *big.Int) {
	// EIP161: We must check emptiness for the objects such that the account
	// clearing (0,0,0 objects) can take effect.
	if amount.Sign() == 0 {
		if s.empty() {
			s.touch()
		}
		return
	}
	s.SetBalance(new(big.Int).Add(s.Balance(), amount))
}

// SubBalance removes amount from s's balance.
// It is used to remove funds from the origin account of a transfer.
func (s *StateObject) SubBalance(amount *big.Int) {
	if amount.Sign() == 0 {
		return
	}
	s.SetBalance(new(big.Int).Sub(s.Balance(), amount))
}

func (s *StateObject) SetBalance(amount *big.Int) {
	s.db.journal.append(balanceChange{
		account: &s.address,
		prev:    new(big.Int).Set(s.data.Balance),
	})
	s.setBalance(amount)
}

func (s *StateObject) setBalance(amount *big.Int) {
	s.data.Balance = amount
}

// Return the gas back to the origin. Used by the Virtual machine or Closures
func (s *StateObject) ReturnGas(gas *big.Int) {}

func (s *StateObject) deepCopy(db *StateDB) *StateObject {
	stateObject := newObject(db, s.isParallel, s.address, s.data)
	if s.trie != nil {
		stateObject.trie = db.db.CopyTrie(s.trie)
	}
	stateObject.code = s.code
	stateObject.dirtyStorage = s.dirtyStorage.Copy()
	stateObject.originStorage = s.originStorage.Copy()
	stateObject.pendingStorage = s.pendingStorage.Copy()
	stateObject.suicided = s.suicided
	stateObject.dirtyCode = s.dirtyCode
	stateObject.deleted = s.deleted
	return stateObject
}

func (s *StateObject) MergeSlotObject(db Database, dirtyObjs *StateObject, keys StateKeys) {
	for key := range keys {
		// better to do s.GetState(db, key) to load originStorage for this key?
		// since originStorage was in dirtyObjs, but it works even originStorage miss the state object.
		s.SetState(db, key, dirtyObjs.GetState(db, key))
	}
}

//
// Attribute accessors
//

// Returns the address of the contract/account
func (s *StateObject) Address() common.Address {
	return s.address
}

// Code returns the contract code associated with this object, if any.
func (s *StateObject) Code(db Database) []byte {
	if s.code != nil {
		return s.code
	}
	if bytes.Equal(s.CodeHash(), emptyCodeHash) {
		return nil
	}
	code, err := db.ContractCode(s.addrHash, common.BytesToHash(s.CodeHash()))
	if err != nil {
		s.setError(fmt.Errorf("can't load code hash %x: %v", s.CodeHash(), err))
	}
	s.code = code
	return code
}

// CodeSize returns the size of the contract code associated with this object,
// or zero if none. This method is an almost mirror of Code, but uses a cache
// inside the database to avoid loading codes seen recently.
func (s *StateObject) CodeSize(db Database) int {
	if s.code != nil {
		return len(s.code)
	}
	if bytes.Equal(s.CodeHash(), emptyCodeHash) {
		return 0
	}
	size, err := db.ContractCodeSize(s.addrHash, common.BytesToHash(s.CodeHash()))
	if err != nil {
		s.setError(fmt.Errorf("can't load code size %x: %v", s.CodeHash(), err))
	}
	return size
}

func (s *StateObject) SetCode(codeHash common.Hash, code []byte) {
	prevcode := s.Code(s.db.db)
	s.db.journal.append(codeChange{
		account:  &s.address,
		prevhash: s.CodeHash(),
		prevcode: prevcode,
	})
	s.setCode(codeHash, code)
}

func (s *StateObject) setCode(codeHash common.Hash, code []byte) {
	s.code = code
	s.data.CodeHash = codeHash[:]
	s.dirtyCode = true
}

func (s *StateObject) SetNonce(nonce uint64) {
	s.db.journal.append(nonceChange{
		account: &s.address,
		prev:    s.data.Nonce,
	})
	s.setNonce(nonce)
}

func (s *StateObject) setNonce(nonce uint64) {
	s.data.Nonce = nonce
}

func (s *StateObject) CodeHash() []byte {
	return s.data.CodeHash
}

func (s *StateObject) Balance() *big.Int {
	return s.data.Balance
}

func (s *StateObject) Nonce() uint64 {
	return s.data.Nonce
}

// Never called, but must be present to allow StateObject to be used
// as a vm.Account interface that also satisfies the vm.ContractRef
// interface. Interfaces are awesome.
func (s *StateObject) Value() *big.Int {
	panic("Value on StateObject should never be called")
}
