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

// Package state provides a caching layer atop the Ethereum state trie.
package state

import (
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/gopool"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

const (
	preLoadLimit      = 128
	defaultNumOfSlots = 100
)

type revision struct {
	id           int
	journalIndex int
}

var (
	// emptyRoot is the known root hash of an empty trie.
	emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

	emptyAddr = crypto.Keccak256Hash(common.Address{}.Bytes())
)

type proofList [][]byte

func (n *proofList) Put(key []byte, value []byte) error {
	*n = append(*n, value)
	return nil
}

func (n *proofList) Delete(key []byte) error {
	panic("not supported")
}

type StateKeys map[common.Hash]struct{}

type StateObjectSyncMap struct {
	sync.Map
}

func (s *StateObjectSyncMap) LoadStateObject(addr common.Address) (*StateObject, bool) {
	stateObject, ok := s.Load(addr)
	if !ok {
		return nil, ok
	}
	return stateObject.(*StateObject), ok
}

func (s *StateObjectSyncMap) StoreStateObject(addr common.Address, stateObject *StateObject) {
	s.Store(addr, stateObject)
}

// loadStateObj is the entry for loading state object from stateObjects in StateDB or stateObjects in parallel
func (s *StateDB) loadStateObj(addr common.Address) (*StateObject, bool) {
	if s.isParallel {
		return s.parallel.stateObjects.LoadStateObject(addr)
	}
	obj, ok := s.stateObjects[addr]
	return obj, ok
}

// storeStateObj is the entry for storing state object to stateObjects in StateDB or stateObjects in parallel
func (s *StateDB) storeStateObj(addr common.Address, stateObject *StateObject) {
	if s.isParallel {
		s.parallel.stateObjects.Store(addr, stateObject)
	} else {
		s.stateObjects[addr] = stateObject
	}
}

// deleteStateObj is the entry for deleting state object to stateObjects in StateDB or stateObjects in parallel
func (s *StateDB) deleteStateObj(addr common.Address) {
	if s.isParallel {
		s.parallel.stateObjects.Delete(addr)
	} else {
		delete(s.stateObjects, addr)
	}
}

// For parallel mode only, keep the change list for later conflict detect
type SlotChangeList struct {
	TxIndex             int
	StateObjectSuicided map[common.Address]struct{}
	StateChangeSet      map[common.Address]StateKeys
	BalanceChangeSet    map[common.Address]struct{}
	CodeChangeSet       map[common.Address]struct{}
	AddrStateChangeSet  map[common.Address]struct{}
	NonceChangeSet      map[common.Address]struct{}
}

// For parallel mode only
type ParallelState struct {
	isSlotDB bool // isSlotDB denotes StateDB is used in slot

	// stateObjects holds the state objects in the base slot db
	// the reason for using stateObjects instead of stateObjects on the outside is
	// we need a thread safe map to hold state objects since there are many slots will read
	// state objects from it;
	// And we will merge all the changes made by the concurrent slot into it.
	stateObjects *StateObjectSyncMap

	baseTxIndex               int // slotDB is created base on this tx index.
	dirtiedStateObjectsInSlot map[common.Address]*StateObject
	// for conflict check
	balanceChangesInSlot map[common.Address]struct{} // the address's balance has been changed
	balanceReadsInSlot   map[common.Address]struct{} // the address's balance has been read and used.
	codeReadsInSlot      map[common.Address]struct{}
	codeChangesInSlot    map[common.Address]struct{}
	stateReadsInSlot     map[common.Address]StateKeys
	stateChangesInSlot   map[common.Address]StateKeys // no need record value
	// Actions such as SetCode, Suicide will change address's state.
	// Later call like Exist(), Empty(), HasSuicided() depend on the address's state.
	addrStateReadsInSlot       map[common.Address]struct{}
	addrStateChangesInSlot     map[common.Address]struct{}
	stateObjectsSuicidedInSlot map[common.Address]struct{}
	nonceChangesInSlot         map[common.Address]struct{}
	// Transaction will pay gas fee to system address.
	// Parallel execution will clear system address's balance at first, in order to maintain transaction's
	// gas fee value. Normal transaction will access system address twice, otherwise it means the transaction
	// needs real system address's balance, the transaction will be marked redo with keepSystemAddressBalance = true
	systemAddress            common.Address
	systemAddressOpsCount    int
	keepSystemAddressBalance bool

	// we may need to redo for some specific reasons, like we read the wrong state and need to panic in sequential mode in SubRefund
	needRedo bool
}

// StateDB structs within the ethereum protocol are used to store anything
// within the merkle trie. StateDBs take care of caching and storing
// nested states. It's the general query interface to retrieve:
// * Contracts
// * Accounts
type StateDB struct {
	db             Database
	prefetcherLock sync.Mutex
	prefetcher     *triePrefetcher
	originalRoot   common.Hash // The pre-state root, before any changes were made
	expectedRoot   common.Hash // The state root in the block header
	stateRoot      common.Hash // The calculation result of IntermediateRoot

	trie           Trie
	hasher         crypto.KeccakState
	diffLayer      *types.DiffLayer
	diffTries      map[common.Address]Trie
	diffCode       map[common.Hash][]byte
	lightProcessed bool
	fullProcessed  bool
	pipeCommit     bool

	snapMux       sync.Mutex
	snaps         *snapshot.Tree
	snap          snapshot.Snapshot
	snapDestructs map[common.Address]struct{}
	snapAccounts  map[common.Address][]byte
	snapStorage   map[common.Address]map[string][]byte

	// This map holds 'live' objects, which will get modified while processing a state transition.
	stateObjects        map[common.Address]*StateObject
	stateObjectsPending map[common.Address]struct{} // State objects finalized but not yet written to the trie
	stateObjectsDirty   map[common.Address]struct{} // State objects modified in the current execution

	isParallel bool
	parallel   ParallelState // to keep all the parallel execution elements

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be returned
	// by StateDB.Commit.
	dbErr error

	// The refund counter, also used by state transitioning.
	refund uint64

	thash, bhash common.Hash
	txIndex      int
	logs         map[common.Hash][]*types.Log
	logSize      uint

	preimages map[common.Hash][]byte

	// Per-transaction access list
	accessList *accessList

	// Journal of state modifications. This is the backbone of
	// Snapshot and RevertToSnapshot.
	journal        *journal
	validRevisions []revision
	nextRevisionId int

	// Measurements gathered during execution for debugging purposes
	MetricsMux           sync.Mutex
	AccountReads         time.Duration
	AccountHashes        time.Duration
	AccountUpdates       time.Duration
	AccountCommits       time.Duration
	StorageReads         time.Duration
	StorageHashes        time.Duration
	StorageUpdates       time.Duration
	StorageCommits       time.Duration
	SnapshotAccountReads time.Duration
	SnapshotStorageReads time.Duration
	SnapshotCommits      time.Duration
}

// New creates a new state from a given trie.
func New(root common.Hash, db Database, snaps *snapshot.Tree) (*StateDB, error) {
	return newStateDB(root, db, snaps)
}

// NewSlotDB creates a new State DB based on the provided StateDB.
// With parallel, each execution slot would have its own StateDB.
func NewSlotDB(db *StateDB, systemAddr common.Address, baseTxIndex int, keepSystem bool) *StateDB {
	slotDB := db.CopyForSlot()
	slotDB.originalRoot = db.originalRoot
	slotDB.parallel.baseTxIndex = baseTxIndex
	slotDB.parallel.systemAddress = systemAddr
	slotDB.parallel.systemAddressOpsCount = 0
	slotDB.parallel.keepSystemAddressBalance = keepSystem

	// All transactions will pay gas fee to the systemAddr at the end, this address is
	// deemed to conflict, we handle it specially, clear it now and set it back to the main
	// StateDB later;
	// But there are transactions that will try to read systemAddr's balance, such as:
	// https://bscscan.com/tx/0xcd69755be1d2f55af259441ff5ee2f312830b8539899e82488a21e85bc121a2a.
	// It will trigger transaction redo and keepSystem will be marked as true.
	if !keepSystem {
		slotDB.SetBalance(systemAddr, big.NewInt(0))
	}

	return slotDB
}

func newStateDB(root common.Hash, db Database, snaps *snapshot.Tree) (*StateDB, error) {
	sdb := &StateDB{
		db:                  db,
		originalRoot:        root,
		snaps:               snaps,
		stateObjects:        make(map[common.Address]*StateObject, defaultNumOfSlots),
		parallel:            ParallelState{},
		stateObjectsPending: make(map[common.Address]struct{}, defaultNumOfSlots),
		stateObjectsDirty:   make(map[common.Address]struct{}, defaultNumOfSlots),
		logs:                make(map[common.Hash][]*types.Log, defaultNumOfSlots),
		preimages:           make(map[common.Hash][]byte),
		journal:             newJournal(),
		hasher:              crypto.NewKeccakState(),
	}
	if sdb.snaps != nil {
		if sdb.snap = sdb.snaps.Snapshot(root); sdb.snap != nil {
			sdb.snapDestructs = make(map[common.Address]struct{})
			sdb.snapAccounts = make(map[common.Address][]byte)
			sdb.snapStorage = make(map[common.Address]map[string][]byte)
		}
	}

	snapVerified := sdb.snap != nil && sdb.snap.Verified()
	tr, err := db.OpenTrie(root)
	// return error when 1. failed to open trie and 2. the snap is nil or the snap is not nil and done verification
	if err != nil && (sdb.snap == nil || snapVerified) {
		return nil, err
	}
	sdb.trie = tr
	return sdb, nil
}

func (s *StateDB) getStateObjectFromStateObjects(addr common.Address) (*StateObject, bool) {
	if s.parallel.isSlotDB {
		obj, ok := s.parallel.dirtiedStateObjectsInSlot[addr]
		if ok {
			return obj, ok
		}
	}
	return s.loadStateObj(addr)
}

// RevertSlotDB keep its read list for conflict detect and discard its state changes except its own balance change,
// if the transaction execution is reverted,
func (s *StateDB) RevertSlotDB(from common.Address) {
	s.parallel.stateObjectsSuicidedInSlot = make(map[common.Address]struct{})
	s.parallel.stateChangesInSlot = make(map[common.Address]StateKeys)
	s.parallel.balanceChangesInSlot = make(map[common.Address]struct{}, 1)
	s.parallel.balanceChangesInSlot[from] = struct{}{}
	s.parallel.addrStateChangesInSlot = make(map[common.Address]struct{})
	s.parallel.nonceChangesInSlot = make(map[common.Address]struct{})
}

// PrepareForParallel prepares for state db to be used in parallel execution mode.
func (s *StateDB) PrepareForParallel() {
	s.isParallel = true
	s.parallel.stateObjects = &StateObjectSyncMap{}
}

// MergeSlotDB is for Parallel execution mode, when the transaction has been
// finalized(dirty -> pending) on execution slot, the execution results should be
// merged back to the main StateDB.
// And it will return and keep the slot's change list for later conflict detect.
func (s *StateDB) MergeSlotDB(slotDb *StateDB, slotReceipt *types.Receipt, txIndex int) SlotChangeList {
	// receipt.Logs use unified log index within a block
	// align slotDB's log index to the block stateDB's logSize
	for _, l := range slotReceipt.Logs {
		l.Index += s.logSize
	}
	s.logSize += slotDb.logSize

	// before merge, pay the gas fee first: AddBalance to consensus.SystemAddress
	systemAddress := slotDb.parallel.systemAddress
	if slotDb.parallel.keepSystemAddressBalance {
		s.SetBalance(systemAddress, slotDb.GetBalance(systemAddress))
	} else {
		s.AddBalance(systemAddress, slotDb.GetBalance(systemAddress))
	}

	// only merge dirty objects
	addressesToPrefetch := make([][]byte, 0, len(slotDb.stateObjectsDirty))
	for addr := range slotDb.stateObjectsDirty {
		if _, exist := s.stateObjectsDirty[addr]; !exist {
			s.stateObjectsDirty[addr] = struct{}{}
		}
		// system address is EOA account, it should have no storage change
		if addr == systemAddress {
			continue
		}

		// stateObjects: KV, balance, nonce...
		dirtyObj, ok := slotDb.getStateObjectFromStateObjects(addr)
		if !ok {
			log.Error("parallel merge, but dirty object not exist!", "txIndex:", slotDb.txIndex, "addr", addr)
			continue
		}
		mainObj, exist := s.loadStateObj(addr)
		if !exist {
			// addr not exist on main DB, do ownership transfer
			dirtyObj.db = s
			dirtyObj.finalise(true) // true: prefetch on dispatcher
			s.storeStateObj(addr, dirtyObj)
			delete(slotDb.parallel.dirtiedStateObjectsInSlot, addr) // transfer ownership
		} else {
			// addr already in main DB, do merge: balance, KV, code, State(create, suicide)
			// can not do copy or ownership transfer directly, since dirtyObj could have outdated
			// data(may be updated within the conflict window)

			var newMainObj = mainObj // we don't need to copy the object since the storages are thread safe
			if _, created := slotDb.parallel.addrStateChangesInSlot[addr]; created {
				// there are 3 kinds of state change:
				// 1.Suicide
				// 2.Empty Delete
				// 3.createObject
				//   a.AddBalance,SetState to an unexist or deleted(suicide, empty delete) address.
				//   b.CreateAccount: like DAO the fork, regenerate a account carry its balance without KV
				// For these state change, do ownership transafer for efficiency:
				log.Debug("MergeSlotDB state object merge: addr state change")
				dirtyObj.db = s
				newMainObj = dirtyObj
				delete(slotDb.parallel.dirtiedStateObjectsInSlot, addr) // transfer ownership
				if dirtyObj.deleted {
					// remove the addr from snapAccounts&snapStorage only when object is deleted.
					// "deleted" is not equal to "snapDestructs", since createObject() will add an addr for
					//  snapDestructs to destroy previous object, while it will keep the addr in snapAccounts & snapAccounts
					delete(s.snapAccounts, addr)
					delete(s.snapStorage, addr)
				}
			} else {
				// deepCopy a temporary *StateObject for safety, since slot could read the address,
				// dispatch should avoid overwrite the StateObject directly otherwise, it could
				// crash for: concurrent map iteration and map write
				if _, balanced := slotDb.parallel.balanceChangesInSlot[addr]; balanced {
					log.Debug("merge state object: Balance",
						"newMainObj.Balance()", newMainObj.Balance(),
						"dirtyObj.Balance()", dirtyObj.Balance())
					newMainObj.SetBalance(dirtyObj.Balance())
				}
				if _, coded := slotDb.parallel.codeChangesInSlot[addr]; coded {
					log.Debug("merge state object: Code")
					newMainObj.code = dirtyObj.code
					newMainObj.data.CodeHash = dirtyObj.data.CodeHash
					newMainObj.dirtyCode = true
				}
				if keys, stated := slotDb.parallel.stateChangesInSlot[addr]; stated {
					log.Debug("merge state object: KV")
					newMainObj.MergeSlotObject(s.db, dirtyObj, keys)
				}
				// dirtyObj.Nonce() should not be less than newMainObj
				newMainObj.setNonce(dirtyObj.Nonce())
			}
			newMainObj.finalise(true) // true: prefetch on dispatcher
			// update the object
			s.storeStateObj(addr, newMainObj)
		}
		addressesToPrefetch = append(addressesToPrefetch, common.CopyBytes(addr[:])) // Copy needed for closure
	}

	if s.prefetcher != nil && len(addressesToPrefetch) > 0 {
		s.prefetcher.prefetch(s.originalRoot, addressesToPrefetch, emptyAddr) // prefetch for trie node of account
	}

	for addr := range slotDb.stateObjectsPending {
		if _, exist := s.stateObjectsPending[addr]; !exist {
			s.stateObjectsPending[addr] = struct{}{}
		}
	}

	// slotDb.logs: logs will be kept in receipts, no need to do merge

	for hash, preimage := range slotDb.preimages {
		s.preimages[hash] = preimage
	}
	if s.accessList != nil {
		// fixme: accessList is not enabled yet, but it should use merge rather than overwrite Copy
		s.accessList = slotDb.accessList.Copy()
	}

	if slotDb.snaps != nil {
		for k := range slotDb.snapDestructs {
			// There could be a race condition for parallel transaction execution
			// One transaction add balance 0 to an empty address, will delete it(delete empty is enabled).
			// While another concurrent transaction could add a none-zero balance to it, make it not empty
			// We fixed it by add a addr state read record for add balance 0
			s.snapDestructs[k] = struct{}{}
		}

		// slotDb.snapAccounts should be empty, comment out and to be deleted later
		// for k, v := range slotDb.snapAccounts {
		//	s.snapAccounts[k] = v
		// }
		// slotDb.snapStorage should be empty, comment out and to be deleted later
		// for k, v := range slotDb.snapStorage {
		// 	temp := make(map[string][]byte)
		//	for kk, vv := range v {
		//		temp[kk] = vv
		//	}
		//	s.snapStorage[k] = temp
		// }
	}

	// to create a new object to store change list for conflict detect,
	// since slot db reuse is disabled, we do not need to do copy.
	changeList := SlotChangeList{
		TxIndex:             txIndex,
		StateObjectSuicided: slotDb.parallel.stateObjectsSuicidedInSlot,
		StateChangeSet:      slotDb.parallel.stateChangesInSlot,
		BalanceChangeSet:    slotDb.parallel.balanceChangesInSlot,
		CodeChangeSet:       slotDb.parallel.codeChangesInSlot,
		AddrStateChangeSet:  slotDb.parallel.addrStateChangesInSlot,
		NonceChangeSet:      slotDb.parallel.nonceChangesInSlot,
	}
	return changeList
}

// StartPrefetcher initializes a new trie prefetcher to pull in nodes from the
// state trie concurrently while the state is mutated so that when we reach the
// commit phase, most of the needed data is already hot.
func (s *StateDB) StartPrefetcher(namespace string) {
	s.prefetcherLock.Lock()
	defer s.prefetcherLock.Unlock()
	if s.prefetcher != nil {
		s.prefetcher.close()
		s.prefetcher = nil
	}
	if s.snap != nil {
		s.prefetcher = newTriePrefetcher(s.db, s.originalRoot, namespace)
	}
}

// StopPrefetcher terminates a running prefetcher and reports any leftover stats
// from the gathered metrics.
func (s *StateDB) StopPrefetcher() {
	s.prefetcherLock.Lock()
	defer s.prefetcherLock.Unlock()
	if s.prefetcher != nil {
		s.prefetcher.close()
		s.prefetcher = nil
	}
}

// Mark that the block is processed by diff layer
func (s *StateDB) SetExpectedStateRoot(root common.Hash) {
	s.expectedRoot = root
}

// Mark that the block is processed by diff layer
func (s *StateDB) MarkLightProcessed() {
	s.lightProcessed = true
}

// Enable the pipeline commit function of statedb
func (s *StateDB) EnablePipeCommit() {
	if s.snap != nil {
		s.pipeCommit = true
	}
}

// Mark that the block is full processed
func (s *StateDB) MarkFullProcessed() {
	s.fullProcessed = true
}

func (s *StateDB) IsLightProcessed() bool {
	return s.lightProcessed
}

// setError remembers the first non-nil error it is called with.
func (s *StateDB) setError(err error) {
	if s.dbErr == nil {
		s.dbErr = err
	}
}

func (s *StateDB) Error() error {
	return s.dbErr
}

// Not thread safe
func (s *StateDB) Trie() (Trie, error) {
	if s.trie == nil {
		err := s.WaitPipeVerification()
		if err != nil {
			return nil, err
		}
		tr, err := s.db.OpenTrie(s.originalRoot)
		if err != nil {
			return nil, err
		}
		s.trie = tr
	}
	return s.trie, nil
}

func (s *StateDB) SetDiff(diffLayer *types.DiffLayer, diffTries map[common.Address]Trie, diffCode map[common.Hash][]byte) {
	s.diffLayer, s.diffTries, s.diffCode = diffLayer, diffTries, diffCode
}

func (s *StateDB) SetSnapData(snapDestructs map[common.Address]struct{}, snapAccounts map[common.Address][]byte,
	snapStorage map[common.Address]map[string][]byte) {
	s.snapDestructs, s.snapAccounts, s.snapStorage = snapDestructs, snapAccounts, snapStorage
}

func (s *StateDB) AddLog(log *types.Log) {
	s.journal.append(addLogChange{txhash: s.thash})

	log.TxHash = s.thash
	log.BlockHash = s.bhash
	log.TxIndex = uint(s.txIndex)
	log.Index = s.logSize
	s.logs[s.thash] = append(s.logs[s.thash], log)
	s.logSize++
}

func (s *StateDB) GetLogs(hash common.Hash) []*types.Log {
	return s.logs[hash]
}

func (s *StateDB) Logs() []*types.Log {
	var logs []*types.Log
	for _, lgs := range s.logs {
		logs = append(logs, lgs...)
	}
	return logs
}

// AddPreimage records a SHA3 preimage seen by the VM.
func (s *StateDB) AddPreimage(hash common.Hash, preimage []byte) {
	if _, ok := s.preimages[hash]; !ok {
		s.journal.append(addPreimageChange{hash: hash})
		pi := make([]byte, len(preimage))
		copy(pi, preimage)
		s.preimages[hash] = pi
	}
}

// Preimages returns a list of SHA3 preimages that have been submitted.
func (s *StateDB) Preimages() map[common.Hash][]byte {
	return s.preimages
}

// AddRefund adds gas to the refund counter
func (s *StateDB) AddRefund(gas uint64) {
	s.journal.append(refundChange{prev: s.refund})
	s.refund += gas
}

// SubRefund removes gas from the refund counter.
// This method will panic if the refund counter goes below zero
func (s *StateDB) SubRefund(gas uint64) {
	s.journal.append(refundChange{prev: s.refund})
	if gas > s.refund {
		if s.isParallel {
			// we don't need to panic here if we read the wrong state, we just need to redo this transaction
			log.Info(fmt.Sprintf("Refund counter below zero (gas: %d > refund: %d)", gas, s.refund), "tx", s.thash.String())
			s.parallel.needRedo = true
			return
		}
		panic(fmt.Sprintf("Refund counter below zero (gas: %d > refund: %d)", gas, s.refund))
	}
	s.refund -= gas
}

// Exist reports whether the given account address exists in the state.
// Notably this also returns true for suicided accounts.
func (s *StateDB) Exist(addr common.Address) bool {
	return s.getStateObject(addr) != nil
}

// Empty returns whether the state object is either non-existent
// or empty according to the EIP161 specification (balance = nonce = code = 0)
func (s *StateDB) Empty(addr common.Address) bool {
	so := s.getStateObject(addr)
	return so == nil || so.empty()
}

// GetBalance retrieves the balance from the given address or 0 if object not found
func (s *StateDB) GetBalance(addr common.Address) *big.Int {
	if s.parallel.isSlotDB {
		s.parallel.balanceReadsInSlot[addr] = struct{}{}
		if addr == s.parallel.systemAddress {
			s.parallel.systemAddressOpsCount++
		}
	}
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Balance()
	}
	return common.Big0
}

func (s *StateDB) GetNonce(addr common.Address) uint64 {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Nonce()
	}
	return 0
}

// TxIndex returns the current transaction index set by Prepare.
func (s *StateDB) TxIndex() int {
	return s.txIndex
}

// BlockHash returns the current block hash set by Prepare.
func (s *StateDB) BlockHash() common.Hash {
	return s.bhash
}

// BaseTxIndex returns the tx index that slot db based.
func (s *StateDB) BaseTxIndex() int {
	return s.parallel.baseTxIndex
}

func (s *StateDB) CodeReadsInSlot() map[common.Address]struct{} {
	return s.parallel.codeReadsInSlot
}

func (s *StateDB) AddressReadsInSlot() map[common.Address]struct{} {
	return s.parallel.addrStateReadsInSlot
}

func (s *StateDB) StateReadsInSlot() map[common.Address]StateKeys {
	return s.parallel.stateReadsInSlot
}

func (s *StateDB) BalanceReadsInSlot() map[common.Address]struct{} {
	return s.parallel.balanceReadsInSlot
}

// For most of the transactions, systemAddressOpsCount should be 2:
//  one for SetBalance(0) on NewSlotDB()
//  the other is for AddBalance(GasFee) at the end.
// (systemAddressOpsCount > 2) means the transaction tries to access systemAddress, in
// this case, we should redo and keep its balance on NewSlotDB()
func (s *StateDB) SystemAddressRedo() bool {
	return s.parallel.systemAddressOpsCount > 2
}

// NeedRedo returns true if there is any clear reason that we need to redo this transaction
func (s *StateDB) NeedRedo() bool {
	return s.parallel.needRedo
}

func (s *StateDB) GetCode(addr common.Address) []byte {
	if s.parallel.isSlotDB {
		s.parallel.codeReadsInSlot[addr] = struct{}{}
	}

	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Code(s.db)
	}
	return nil
}

func (s *StateDB) GetCodeSize(addr common.Address) int {
	if s.parallel.isSlotDB {
		s.parallel.codeReadsInSlot[addr] = struct{}{} // code size is part of code
	}

	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.CodeSize(s.db)
	}
	return 0
}

func (s *StateDB) GetCodeHash(addr common.Address) common.Hash {
	if s.parallel.isSlotDB {
		s.parallel.codeReadsInSlot[addr] = struct{}{} // code hash is part of code
	}

	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return common.Hash{}
	}
	return common.BytesToHash(stateObject.CodeHash())
}

// GetState retrieves a value from the given account's storage trie.
func (s *StateDB) GetState(addr common.Address, hash common.Hash) common.Hash {
	if s.parallel.isSlotDB {
		if s.parallel.stateReadsInSlot[addr] == nil {
			s.parallel.stateReadsInSlot[addr] = make(map[common.Hash]struct{}, defaultNumOfSlots)
		}
		s.parallel.stateReadsInSlot[addr][hash] = struct{}{}
	}

	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetState(s.db, hash)
	}
	return common.Hash{}
}

// GetProof returns the Merkle proof for a given account.
func (s *StateDB) GetProof(addr common.Address) ([][]byte, error) {
	return s.GetProofByHash(crypto.Keccak256Hash(addr.Bytes()))
}

// GetProofByHash returns the Merkle proof for a given account.
func (s *StateDB) GetProofByHash(addrHash common.Hash) ([][]byte, error) {
	var proof proofList
	if _, err := s.Trie(); err != nil {
		return nil, err
	}
	err := s.trie.Prove(addrHash[:], 0, &proof)
	return proof, err
}

// GetStorageProof returns the Merkle proof for given storage slot.
func (s *StateDB) GetStorageProof(a common.Address, key common.Hash) ([][]byte, error) {
	var proof proofList
	trie := s.StorageTrie(a)
	if trie == nil {
		return proof, errors.New("storage trie for requested address does not exist")
	}
	err := trie.Prove(crypto.Keccak256(key.Bytes()), 0, &proof)
	return proof, err
}

// GetStorageProofByHash returns the Merkle proof for given storage slot.
func (s *StateDB) GetStorageProofByHash(a common.Address, key common.Hash) ([][]byte, error) {
	var proof proofList
	trie := s.StorageTrie(a)
	if trie == nil {
		return proof, errors.New("storage trie for requested address does not exist")
	}
	err := trie.Prove(crypto.Keccak256(key.Bytes()), 0, &proof)
	return proof, err
}

// GetCommittedState retrieves a value from the given account's committed storage trie.
func (s *StateDB) GetCommittedState(addr common.Address, hash common.Hash) common.Hash {
	if s.parallel.isSlotDB {
		if s.parallel.stateReadsInSlot[addr] == nil {
			s.parallel.stateReadsInSlot[addr] = make(map[common.Hash]struct{}, defaultNumOfSlots)
		}
		s.parallel.stateReadsInSlot[addr][hash] = struct{}{}
	}

	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetCommittedState(s.db, hash)
	}
	return common.Hash{}
}

// Database retrieves the low level database supporting the lower level trie ops.
func (s *StateDB) Database() Database {
	return s.db
}

// StorageTrie returns the storage trie of an account.
// The return value is a copy and is nil for non-existent accounts.
func (s *StateDB) StorageTrie(addr common.Address) Trie {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return nil
	}
	cpy := stateObject.deepCopy(s)
	cpy.updateTrie(s.db)
	return cpy.getTrie(s.db)
}

func (s *StateDB) HasSuicided(addr common.Address) bool {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.suicided
	}
	return false
}

/*
 * SETTERS
 */

// AddBalance adds amount to the account associated with addr.
func (s *StateDB) AddBalance(addr common.Address, amount *big.Int) {
	if s.parallel.isSlotDB {
		if amount.Sign() != 0 {
			s.parallel.balanceChangesInSlot[addr] = struct{}{}
			// add balance will perform a read operation first
			s.parallel.balanceReadsInSlot[addr] = struct{}{}
		} else {
			// if amount == 0, no balance change, but there is still an empty check.
			// take this empty check as addr state read(create, suicide, empty delete)
			s.parallel.addrStateReadsInSlot[addr] = struct{}{}
		}
		if addr == s.parallel.systemAddress {
			s.parallel.systemAddressOpsCount++
		}
	}

	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		if s.parallel.isSlotDB {
			if _, ok := s.parallel.dirtiedStateObjectsInSlot[addr]; !ok {
				newStateObject := stateObject.deepCopy(s)
				newStateObject.AddBalance(amount)
				s.parallel.dirtiedStateObjectsInSlot[addr] = newStateObject
				return
			}
		}
		stateObject.AddBalance(amount)
	}
}

// SubBalance subtracts amount from the account associated with addr.
func (s *StateDB) SubBalance(addr common.Address, amount *big.Int) {
	if s.parallel.isSlotDB {
		if amount.Sign() != 0 {
			s.parallel.balanceChangesInSlot[addr] = struct{}{}
			// unlike add, sub 0 balance will not touch empty object
			s.parallel.balanceReadsInSlot[addr] = struct{}{}
		}
		if addr == s.parallel.systemAddress {
			s.parallel.systemAddressOpsCount++
		}
	}

	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		if s.parallel.isSlotDB {
			if _, ok := s.parallel.dirtiedStateObjectsInSlot[addr]; !ok {
				newStateObject := stateObject.deepCopy(s)
				newStateObject.SubBalance(amount)
				s.parallel.dirtiedStateObjectsInSlot[addr] = newStateObject
				return
			}
		}
		stateObject.SubBalance(amount)
	}
}

func (s *StateDB) SetBalance(addr common.Address, amount *big.Int) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		if s.parallel.isSlotDB {
			s.parallel.balanceChangesInSlot[addr] = struct{}{}
			if addr == s.parallel.systemAddress {
				s.parallel.systemAddressOpsCount++
			}

			if _, ok := s.parallel.dirtiedStateObjectsInSlot[addr]; !ok {
				newStateObject := stateObject.deepCopy(s)
				newStateObject.SetBalance(amount)
				s.parallel.dirtiedStateObjectsInSlot[addr] = newStateObject
				return
			}
		}
		stateObject.SetBalance(amount)
	}
}

// Generally sender's nonce will be increased by 1 for each transaction
// But if the contract tries to create a new contract, its nonce will be advanced
// for each opCreate or opCreate2. Nonce is key to transaction execution, once it is
// changed for contract created, the concurrent transaction will be marked invalid if
// they accessed the address.
func (s *StateDB) NonceChanged(addr common.Address) {
	if s.parallel.isSlotDB {
		log.Debug("NonceChanged", "txIndex", s.txIndex, "addr", addr)
		s.parallel.nonceChangesInSlot[addr] = struct{}{}
	}
}

func (s *StateDB) SetNonce(addr common.Address, nonce uint64) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		if s.parallel.isSlotDB {
			if _, ok := s.parallel.dirtiedStateObjectsInSlot[addr]; !ok {
				newStateObject := stateObject.deepCopy(s)
				newStateObject.SetNonce(nonce)
				s.parallel.dirtiedStateObjectsInSlot[addr] = newStateObject
				return
			}
		}
		stateObject.SetNonce(nonce)
	}
}

func (s *StateDB) SetCode(addr common.Address, code []byte) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		if s.parallel.isSlotDB {
			s.parallel.codeChangesInSlot[addr] = struct{}{}

			if _, ok := s.parallel.dirtiedStateObjectsInSlot[addr]; !ok {
				newStateObject := stateObject.deepCopy(s)
				newStateObject.SetCode(crypto.Keccak256Hash(code), code)
				s.parallel.dirtiedStateObjectsInSlot[addr] = newStateObject
				return
			}
		}
		stateObject.SetCode(crypto.Keccak256Hash(code), code)
	}
}

func (s *StateDB) SetState(addr common.Address, key, value common.Hash) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		if s.parallel.isSlotDB {
			if s.parallel.baseTxIndex+1 == s.txIndex {
				// we check if state is unchanged
				// only when current transaction is the next transaction to be committed
				if stateObject.GetState(s.db, key) == value {
					log.Debug("Skip set same state", "baseTxIndex", s.parallel.baseTxIndex,
						"txIndex", s.txIndex)
					return
				}
			}

			if s.parallel.stateChangesInSlot[addr] == nil {
				s.parallel.stateChangesInSlot[addr] = make(StateKeys, defaultNumOfSlots)
			}
			s.parallel.stateChangesInSlot[addr][key] = struct{}{}

			if _, ok := s.parallel.dirtiedStateObjectsInSlot[addr]; !ok {
				newStateObject := stateObject.deepCopy(s)
				newStateObject.SetState(s.db, key, value)
				s.parallel.dirtiedStateObjectsInSlot[addr] = newStateObject
				return
			}
		}
		stateObject.SetState(s.db, key, value)
	}
}

// SetStorage replaces the entire storage for the specified account with given
// storage. This function should only be used for debugging.
func (s *StateDB) SetStorage(addr common.Address, storage map[common.Hash]common.Hash) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetStorage(storage)
	}
}

// Suicide marks the given account as suicided.
// This clears the account balance.
//
// The account's state object is still available until the state is committed,
// getStateObject will return a non-nil account after Suicide.
func (s *StateDB) Suicide(addr common.Address) bool {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return false
	}

	s.journal.append(suicideChange{
		account:     &addr,
		prev:        stateObject.suicided,
		prevbalance: new(big.Int).Set(stateObject.Balance()),
	})

	if s.parallel.isSlotDB {
		s.parallel.stateObjectsSuicidedInSlot[addr] = struct{}{}
		s.parallel.addrStateChangesInSlot[addr] = struct{}{}
		if _, ok := s.parallel.dirtiedStateObjectsInSlot[addr]; !ok {
			// do copy-on-write for suicide "write"
			newStateObject := stateObject.deepCopy(s)
			newStateObject.markSuicided()
			newStateObject.data.Balance = new(big.Int)
			s.parallel.dirtiedStateObjectsInSlot[addr] = newStateObject
			return true
		}
	}

	stateObject.markSuicided()
	stateObject.data.Balance = new(big.Int)
	return true
}

//
// Setting, updating & deleting state object methods.
//

// updateStateObject writes the given object to the trie.
func (s *StateDB) updateStateObject(obj *StateObject) {
	// Track the amount of time wasted on updating the account from the trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.AccountUpdates += time.Since(start) }(time.Now())
	}
	// Encode the account and update the account trie
	addr := obj.Address()
	data := obj.encodeData
	var err error
	if data == nil {
		data, err = rlp.EncodeToBytes(obj)
		if err != nil {
			panic(fmt.Errorf("can't encode object at %x: %v", addr[:], err))
		}
	}
	if err = s.trie.TryUpdate(addr[:], data); err != nil {
		s.setError(fmt.Errorf("updateStateObject (%x) error: %v", addr[:], err))
	}
}

// deleteStateObject removes the given object from the state trie.
func (s *StateDB) deleteStateObject(obj *StateObject) {
	// Track the amount of time wasted on deleting the account from the trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.AccountUpdates += time.Since(start) }(time.Now())
	}
	// Delete the account from the trie
	addr := obj.Address()
	if err := s.trie.TryDelete(addr[:]); err != nil {
		s.setError(fmt.Errorf("deleteStateObject (%x) error: %v", addr[:], err))
	}
}

// getStateObject retrieves a state object given by the address, returning nil if
// the object is not found or was deleted in this execution context. If you need
// to differentiate between non-existent/just-deleted, use getDeletedStateObject.
func (s *StateDB) getStateObject(addr common.Address) *StateObject {
	if s.parallel.isSlotDB {
		s.parallel.addrStateReadsInSlot[addr] = struct{}{}
	}

	if obj := s.getDeletedStateObject(addr); obj != nil && !obj.deleted {
		return obj
	}
	return nil
}

func (s *StateDB) TryPreload(block *types.Block, signer types.Signer) {
	accounts := make(map[common.Address]bool, block.Transactions().Len())
	accountsSlice := make([]common.Address, 0, block.Transactions().Len())
	for _, tx := range block.Transactions() {
		from, err := types.Sender(signer, tx)
		if err != nil {
			break
		}
		accounts[from] = true
		if tx.To() != nil {
			accounts[*tx.To()] = true
		}
	}
	for account := range accounts {
		accountsSlice = append(accountsSlice, account)
	}
	if len(accountsSlice) >= preLoadLimit && len(accountsSlice) > runtime.NumCPU() {
		objsChan := make(chan []*StateObject, runtime.NumCPU())
		for i := 0; i < runtime.NumCPU(); i++ {
			start := i * len(accountsSlice) / runtime.NumCPU()
			end := (i + 1) * len(accountsSlice) / runtime.NumCPU()
			if i+1 == runtime.NumCPU() {
				end = len(accountsSlice)
			}
			go func(start, end int) {
				objs := s.preloadStateObject(accountsSlice[start:end])
				objsChan <- objs
			}(start, end)
		}
		for i := 0; i < runtime.NumCPU(); i++ {
			objs := <-objsChan
			for _, obj := range objs {
				s.SetStateObject(obj)
			}
		}
	}
}

func (s *StateDB) preloadStateObject(address []common.Address) []*StateObject {
	// Prefer live objects if any is available
	if s.snap == nil {
		return nil
	}
	hasher := crypto.NewKeccakState()
	objs := make([]*StateObject, 0, len(address))
	for _, addr := range address {
		// If no live objects are available, attempt to use snapshots
		if acc, err := s.snap.Account(crypto.HashData(hasher, addr.Bytes())); err == nil {
			if acc == nil {
				continue
			}
			data := &Account{
				Nonce:    acc.Nonce,
				Balance:  acc.Balance,
				CodeHash: acc.CodeHash,
				Root:     common.BytesToHash(acc.Root),
			}
			if len(data.CodeHash) == 0 {
				data.CodeHash = emptyCodeHash
			}
			if data.Root == (common.Hash{}) {
				data.Root = emptyRoot
			}
			// Insert into the live set
			obj := newObject(s, s.isParallel, addr, *data)
			objs = append(objs, obj)
		}
		// Do not enable this feature when snapshot is not enabled.
	}
	return objs
}

// getDeletedStateObject is similar to getStateObject, but instead of returning
// nil for a deleted state object, it returns the actual object with the deleted
// flag set. This is needed by the state journal to revert to the correct s-
// destructed object instead of wiping all knowledge about the state object.
func (s *StateDB) getDeletedStateObject(addr common.Address) *StateObject {
	// Prefer live objects if any is available
	if obj, _ := s.getStateObjectFromStateObjects(addr); obj != nil {
		return obj
	}
	// If no live objects are available, attempt to use snapshots
	var (
		data *Account
		err  error
	)
	if s.snap != nil {
		if metrics.EnabledExpensive {
			defer func(start time.Time) { s.SnapshotAccountReads += time.Since(start) }(time.Now())
		}
		var acc *snapshot.Account
		if acc, err = s.snap.Account(crypto.HashData(s.hasher, addr.Bytes())); err == nil {
			if acc == nil {
				return nil
			}
			data = &Account{
				Nonce:    acc.Nonce,
				Balance:  acc.Balance,
				CodeHash: acc.CodeHash,
				Root:     common.BytesToHash(acc.Root),
			}
			if len(data.CodeHash) == 0 {
				data.CodeHash = emptyCodeHash
			}
			if data.Root == (common.Hash{}) {
				data.Root = emptyRoot
			}
		}
	}
	// If snapshot unavailable or reading from it failed, load from the database
	if s.snap == nil || err != nil {
		if s.trie == nil {
			tr, err := s.db.OpenTrie(s.originalRoot)
			if err != nil {
				s.setError(fmt.Errorf("failed to open trie tree"))
				return nil
			}
			s.trie = tr
		}
		if metrics.EnabledExpensive {
			defer func(start time.Time) { s.AccountReads += time.Since(start) }(time.Now())
		}
		enc, err := s.trie.TryGet(addr.Bytes())
		if err != nil {
			s.setError(fmt.Errorf("getDeleteStateObject (%x) error: %v", addr.Bytes(), err))
			return nil
		}
		if len(enc) == 0 {
			return nil
		}
		data = new(Account)
		if err := rlp.DecodeBytes(enc, data); err != nil {
			log.Error("Failed to decode state object", "addr", addr, "err", err)
			return nil
		}
	}
	// Insert into the live set
	obj := newObject(s, s.isParallel, addr, *data)
	s.SetStateObject(obj)
	return obj
}

func (s *StateDB) SetStateObject(object *StateObject) {
	if s.parallel.isSlotDB {
		s.parallel.dirtiedStateObjectsInSlot[object.Address()] = object
	} else {
		s.storeStateObj(object.Address(), object)
	}
}

// GetOrNewStateObject retrieves a state object or create a new state object if nil.
func (s *StateDB) GetOrNewStateObject(addr common.Address) *StateObject {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		stateObject, _ = s.createObject(addr)
	}
	return stateObject
}

// createObject creates a new state object. If there is an existing account with
// the given address, it is overwritten and returned as the second return value.
func (s *StateDB) createObject(addr common.Address) (newobj, prev *StateObject) {
	if s.parallel.isSlotDB {
		s.parallel.addrStateReadsInSlot[addr] = struct{}{} // will try to get the previous object.
		s.parallel.addrStateChangesInSlot[addr] = struct{}{}
	}

	prev = s.getDeletedStateObject(addr) // Note, prev might have been deleted, we need that!

	var prevdestruct bool
	if s.snap != nil && prev != nil {
		_, prevdestruct = s.snapDestructs[prev.address]
		if !prevdestruct {
			// createObject for deleted object will destroy the previous trie node first
			// and update the trie tree with the new object on block commit.
			s.snapDestructs[prev.address] = struct{}{}
		}
	}
	newobj = newObject(s, s.isParallel, addr, Account{})
	newobj.setNonce(0) // sets the object to dirty
	if prev == nil {
		s.journal.append(createObjectChange{account: &addr})
	} else {
		s.journal.append(resetObjectChange{prev: prev, prevdestruct: prevdestruct})
	}
	s.SetStateObject(newobj)
	if prev != nil && !prev.deleted {
		return newobj, prev
	}
	return newobj, nil
}

// CreateAccount explicitly creates a state object. If a state object with the address
// already exists the balance is carried over to the new account.
//
// CreateAccount is called during the EVM CREATE operation. The situation might arise that
// a contract does the following:
//
//   1. sends funds to sha(account ++ (nonce + 1))
//   2. tx_create(sha(account ++ nonce)) (note that this gets the address of 1)
//
// Carrying over the balance ensures that Ether doesn't disappear.
func (s *StateDB) CreateAccount(addr common.Address) {
	newObj, prev := s.createObject(addr)
	if prev != nil {
		newObj.setBalance(prev.data.Balance)
	}
	if s.parallel.isSlotDB {
		s.parallel.balanceReadsInSlot[addr] = struct{}{} // read the balance of previous object
		s.parallel.dirtiedStateObjectsInSlot[addr] = newObj
	}
}

func (s *StateDB) ForEachStorage(addr common.Address, cb func(key, value common.Hash) bool) error {
	so := s.getStateObject(addr)
	if so == nil {
		return nil
	}
	it := trie.NewIterator(so.getTrie(s.db).NodeIterator(nil))

	for it.Next() {
		key := common.BytesToHash(s.trie.GetKey(it.Key))
		if value, dirty := so.dirtyStorage.GetValue(key); dirty {
			if !cb(key, value) {
				return nil
			}
			continue
		}

		if len(it.Value) > 0 {
			_, content, _, err := rlp.Split(it.Value)
			if err != nil {
				return err
			}
			if !cb(key, common.BytesToHash(content)) {
				return nil
			}
		}
	}
	return nil
}

// Copy creates a deep, independent copy of the state.
// Snapshots of the copied state cannot be applied to the copy.
func (s *StateDB) Copy() *StateDB {
	// Copy all the basic fields, initialize the memory ones
	state := &StateDB{
		db:                  s.db,
		trie:                s.db.CopyTrie(s.trie),
		stateObjects:        make(map[common.Address]*StateObject, len(s.journal.dirties)),
		stateObjectsPending: make(map[common.Address]struct{}, len(s.stateObjectsPending)),
		stateObjectsDirty:   make(map[common.Address]struct{}, len(s.journal.dirties)),
		refund:              s.refund,
		logs:                make(map[common.Hash][]*types.Log, len(s.logs)),
		logSize:             s.logSize,
		preimages:           make(map[common.Hash][]byte, len(s.preimages)),
		journal:             newJournal(),
		hasher:              crypto.NewKeccakState(),
		parallel:            ParallelState{},
	}
	// Copy the dirty states, logs, and preimages
	for addr := range s.journal.dirties {
		// As documented [here](https://github.com/ethereum/go-ethereum/pull/16485#issuecomment-380438527),
		// and in the Finalise-method, there is a case where an object is in the journal but not
		// in the stateObjects: OOG after touch on ripeMD prior to Byzantium. Thus, we need to check for
		// nil
		if object, exist := s.getStateObjectFromStateObjects(addr); exist {
			// Even though the original object is dirty, we are not copying the journal,
			// so we need to make sure that anyside effect the journal would have caused
			// during a commit (or similar op) is already applied to the copy.
			state.storeStateObj(addr, object.deepCopy(state))

			state.stateObjectsDirty[addr] = struct{}{}   // Mark the copy dirty to force internal (code/state) commits
			state.stateObjectsPending[addr] = struct{}{} // Mark the copy pending to force external (account) commits
		}
	}
	// Above, we don't copy the actual journal. This means that if the copy is copied, the
	// loop above will be a no-op, since the copy's journal is empty.
	// Thus, here we iterate over stateObjects, to enable copies of copies
	for addr := range s.stateObjectsPending {
		if _, exist := state.getStateObjectFromStateObjects(addr); !exist {
			object, _ := s.getStateObjectFromStateObjects(addr)
			state.storeStateObj(addr, object.deepCopy(state))
		}
		state.stateObjectsPending[addr] = struct{}{}
	}
	for addr := range s.stateObjectsDirty {
		if _, exist := state.getStateObjectFromStateObjects(addr); !exist {
			object, _ := s.getStateObjectFromStateObjects(addr)
			state.storeStateObj(addr, object.deepCopy(state))
		}
		state.stateObjectsDirty[addr] = struct{}{}
	}
	for hash, logs := range s.logs {
		cpy := make([]*types.Log, len(logs))
		for i, l := range logs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		state.logs[hash] = cpy
	}
	for hash, preimage := range s.preimages {
		state.preimages[hash] = preimage
	}
	// Do we need to copy the access list? In practice: No. At the start of a
	// transaction, the access list is empty. In practice, we only ever copy state
	// _between_ transactions/blocks, never in the middle of a transaction.
	// However, it doesn't cost us much to copy an empty list, so we do it anyway
	// to not blow up if we ever decide copy it in the middle of a transaction
	if s.accessList != nil {
		state.accessList = s.accessList.Copy()
	}

	// If there's a prefetcher running, make an inactive copy of it that can
	// only access data but does not actively preload (since the user will not
	// know that they need to explicitly terminate an active copy).
	if s.prefetcher != nil {
		state.prefetcher = s.prefetcher.copy()
	}
	if s.snaps != nil {
		// In order for the miner to be able to use and make additions
		// to the snapshot tree, we need to copy that aswell.
		// Otherwise, any block mined by ourselves will cause gaps in the tree,
		// and force the miner to operate trie-backed only
		state.snaps = s.snaps
		state.snap = s.snap
		// deep copy needed
		state.snapDestructs = make(map[common.Address]struct{})
		for k, v := range s.snapDestructs {
			state.snapDestructs[k] = v
		}
		state.snapAccounts = make(map[common.Address][]byte)
		for k, v := range s.snapAccounts {
			state.snapAccounts[k] = v
		}
		state.snapStorage = make(map[common.Address]map[string][]byte)
		for k, v := range s.snapStorage {
			temp := make(map[string][]byte)
			for kk, vv := range v {
				temp[kk] = vv
			}
			state.snapStorage[k] = temp
		}
	}
	return state
}

var addressStructPool = sync.Pool{
	New: func() interface{} { return make(map[common.Address]struct{}, defaultNumOfSlots) },
}

var journalPool = sync.Pool{
	New: func() interface{} {
		return &journal{
			dirties: make(map[common.Address]int, defaultNumOfSlots),
			entries: make([]journalEntry, 0, defaultNumOfSlots),
		}
	},
}

var stateKeysPool = sync.Pool{
	New: func() interface{} { return make(map[common.Address]StateKeys, defaultNumOfSlots) },
}

var stateObjectsPool = sync.Pool{
	New: func() interface{} { return make(map[common.Address]*StateObject, defaultNumOfSlots) },
}

var snapAccountPool = sync.Pool{
	New: func() interface{} { return make(map[common.Address][]byte, defaultNumOfSlots) },
}

var snapStoragePool = sync.Pool{
	New: func() interface{} { return make(map[common.Address]map[string][]byte, defaultNumOfSlots) },
}

var snapStorageValuePool = sync.Pool{
	New: func() interface{} { return make(map[string][]byte, defaultNumOfSlots) },
}

var logsPool = sync.Pool{
	New: func() interface{} { return make(map[common.Hash][]*types.Log, defaultNumOfSlots) },
}

func (s *StateDB) SlotDBPutSyncPool() {
	for key := range s.parallel.stateObjectsSuicidedInSlot {
		delete(s.parallel.stateObjectsSuicidedInSlot, key)
	}
	addressStructPool.Put(s.parallel.stateObjectsSuicidedInSlot)

	for key := range s.parallel.codeReadsInSlot {
		delete(s.parallel.codeReadsInSlot, key)
	}
	addressStructPool.Put(s.parallel.codeReadsInSlot)

	for key := range s.parallel.codeChangesInSlot {
		delete(s.parallel.codeChangesInSlot, key)
	}
	addressStructPool.Put(s.parallel.codeChangesInSlot)

	for key := range s.parallel.balanceChangesInSlot {
		delete(s.parallel.balanceChangesInSlot, key)
	}
	addressStructPool.Put(s.parallel.balanceChangesInSlot)

	for key := range s.parallel.balanceReadsInSlot {
		delete(s.parallel.balanceReadsInSlot, key)
	}
	addressStructPool.Put(s.parallel.balanceReadsInSlot)

	for key := range s.parallel.addrStateReadsInSlot {
		delete(s.parallel.addrStateReadsInSlot, key)
	}
	addressStructPool.Put(s.parallel.addrStateReadsInSlot)

	for key := range s.parallel.nonceChangesInSlot {
		delete(s.parallel.nonceChangesInSlot, key)
	}
	addressStructPool.Put(s.parallel.nonceChangesInSlot)

	for key := range s.stateObjectsPending {
		delete(s.stateObjectsPending, key)
	}
	addressStructPool.Put(s.stateObjectsPending)

	for key := range s.stateObjectsDirty {
		delete(s.stateObjectsDirty, key)
	}
	addressStructPool.Put(s.stateObjectsDirty)

	for key := range s.journal.dirties {
		delete(s.journal.dirties, key)
	}
	s.journal.entries = s.journal.entries[:0]
	journalPool.Put(s.journal)

	for key := range s.parallel.stateChangesInSlot {
		delete(s.parallel.stateChangesInSlot, key)
	}
	stateKeysPool.Put(s.parallel.stateChangesInSlot)

	for key := range s.parallel.stateReadsInSlot {
		delete(s.parallel.stateReadsInSlot, key)
	}
	stateKeysPool.Put(s.parallel.stateReadsInSlot)

	for key := range s.parallel.dirtiedStateObjectsInSlot {
		delete(s.parallel.dirtiedStateObjectsInSlot, key)
	}
	stateObjectsPool.Put(s.parallel.dirtiedStateObjectsInSlot)

	for key := range s.snapDestructs {
		delete(s.snapDestructs, key)
	}
	addressStructPool.Put(s.snapDestructs)

	for key := range s.snapAccounts {
		delete(s.snapAccounts, key)
	}
	snapAccountPool.Put(s.snapAccounts)

	for key, storage := range s.snapStorage {
		for key := range storage {
			delete(storage, key)
		}
		snapStorageValuePool.Put(storage)
		delete(s.snapStorage, key)
	}
	snapStoragePool.Put(s.snapStorage)

	for key := range s.logs {
		delete(s.logs, key)
	}
	logsPool.Put(s.logs)
}

// CopyForSlot copy all the basic fields, initialize the memory ones
func (s *StateDB) CopyForSlot() *StateDB {
	parallel := ParallelState{
		// use base(dispatcher) slot db's stateObjects.
		// It is a SyncMap, only readable to slot, not writable
		stateObjects:               s.parallel.stateObjects,
		stateObjectsSuicidedInSlot: addressStructPool.Get().(map[common.Address]struct{}),
		codeReadsInSlot:            addressStructPool.Get().(map[common.Address]struct{}),
		codeChangesInSlot:          addressStructPool.Get().(map[common.Address]struct{}),
		stateChangesInSlot:         stateKeysPool.Get().(map[common.Address]StateKeys),
		stateReadsInSlot:           stateKeysPool.Get().(map[common.Address]StateKeys),
		balanceChangesInSlot:       addressStructPool.Get().(map[common.Address]struct{}),
		balanceReadsInSlot:         addressStructPool.Get().(map[common.Address]struct{}),
		addrStateReadsInSlot:       addressStructPool.Get().(map[common.Address]struct{}),
		addrStateChangesInSlot:     addressStructPool.Get().(map[common.Address]struct{}),
		nonceChangesInSlot:         addressStructPool.Get().(map[common.Address]struct{}),
		isSlotDB:                   true,
		dirtiedStateObjectsInSlot:  stateObjectsPool.Get().(map[common.Address]*StateObject),
	}
	state := &StateDB{
		db:                  s.db,
		trie:                s.db.CopyTrie(s.trie),
		stateObjects:        make(map[common.Address]*StateObject), // replaced by parallel.stateObjects in parallel mode
		stateObjectsPending: addressStructPool.Get().(map[common.Address]struct{}),
		stateObjectsDirty:   addressStructPool.Get().(map[common.Address]struct{}),
		refund:              s.refund, // should be 0
		logs:                logsPool.Get().(map[common.Hash][]*types.Log),
		logSize:             0,
		preimages:           make(map[common.Hash][]byte, len(s.preimages)),
		journal:             journalPool.Get().(*journal),
		hasher:              crypto.NewKeccakState(),
		isParallel:          true,
		parallel:            parallel,
	}

	for hash, preimage := range s.preimages {
		state.preimages[hash] = preimage
	}

	if s.snaps != nil {
		// In order for the miner to be able to use and make additions
		// to the snapshot tree, we need to copy that aswell.
		// Otherwise, any block mined by ourselves will cause gaps in the tree,
		// and force the miner to operate trie-backed only
		state.snaps = s.snaps
		state.snap = s.snap
		// deep copy needed
		state.snapDestructs = addressStructPool.Get().(map[common.Address]struct{})
		for k, v := range s.snapDestructs {
			state.snapDestructs[k] = v
		}
		//
		state.snapAccounts = snapAccountPool.Get().(map[common.Address][]byte)
		for k, v := range s.snapAccounts {
			state.snapAccounts[k] = v
		}
		state.snapStorage = snapStoragePool.Get().(map[common.Address]map[string][]byte)
		for k, v := range s.snapStorage {
			temp := snapStorageValuePool.Get().(map[string][]byte)
			for kk, vv := range v {
				temp[kk] = vv
			}
			state.snapStorage[k] = temp
		}
		// trie prefetch should be done by dispacther on StateObject Merge,
		// disable it in parallel slot
		// state.prefetcher = s.prefetcher
	}
	return state
}

// Snapshot returns an identifier for the current revision of the state.
func (s *StateDB) Snapshot() int {
	id := s.nextRevisionId
	s.nextRevisionId++
	s.validRevisions = append(s.validRevisions, revision{id, s.journal.length()})
	return id
}

// RevertToSnapshot reverts all state changes made since the given revision.
func (s *StateDB) RevertToSnapshot(revid int) {
	// Find the snapshot in the stack of valid snapshots.
	idx := sort.Search(len(s.validRevisions), func(i int) bool {
		return s.validRevisions[i].id >= revid
	})
	if idx == len(s.validRevisions) || s.validRevisions[idx].id != revid {
		panic(fmt.Errorf("revision id %v cannot be reverted", revid))
	}
	snapshot := s.validRevisions[idx].journalIndex

	// Replay the journal to undo changes and remove invalidated snapshots
	s.journal.revert(s, snapshot)
	s.validRevisions = s.validRevisions[:idx]
}

// GetRefund returns the current value of the refund counter.
func (s *StateDB) GetRefund() uint64 {
	return s.refund
}

// GetRefund returns the current value of the refund counter.
func (s *StateDB) WaitPipeVerification() error {
	// We need wait for the parent trie to commit
	if s.snap != nil {
		if valid := s.snap.WaitAndGetVerifyRes(); !valid {
			return fmt.Errorf("verification on parent snap failed")
		}
	}
	return nil
}

// Finalise finalises the state by removing the s destructed objects and clears
// the journal as well as the refunds. Finalise, however, will not push any updates
// into the tries just yet. Only IntermediateRoot or Commit will do that.
func (s *StateDB) Finalise(deleteEmptyObjects bool) {
	addressesToPrefetch := make([][]byte, 0, len(s.journal.dirties))
	for addr := range s.journal.dirties {
		obj, exist := s.getStateObjectFromStateObjects(addr)
		if !exist {
			// ripeMD is 'touched' at block 1714175, in tx 0x1237f737031e40bcde4a8b7e717b2d15e3ecadfe49bb1bbc71ee9deb09c6fcf2
			// That tx goes out of gas, and although the notion of 'touched' does not exist there, the
			// touch-event will still be recorded in the journal. Since ripeMD is a special snowflake,
			// it will persist in the journal even though the journal is reverted. In this special circumstance,
			// it may exist in `s.journal.dirties` but not in `s.stateObjects`.
			// Thus, we can safely ignore it here
			continue
		}
		if obj.suicided || (deleteEmptyObjects && obj.empty()) {
			if s.parallel.isSlotDB {
				s.parallel.addrStateChangesInSlot[addr] = struct{}{} // empty an StateObject is a state change
			}
			obj.deleted = true

			// If state snapshotting is active, also mark the destruction there.
			// Note, we can't do this only at the end of a block because multiple
			// transactions within the same block might self destruct and then
			// ressurrect an account; but the snapshotter needs both events.
			if s.snap != nil {
				s.snapDestructs[obj.address] = struct{}{} // We need to maintain account deletions explicitly (will remain set indefinitely)
				delete(s.snapAccounts, obj.address)       // Clear out any previously updated account data (may be recreated via a ressurrect)
				delete(s.snapStorage, obj.address)        // Clear out any previously updated storage data (may be recreated via a ressurrect)
			}
		} else {
			// 1.none parallel mode, we do obj.finalise(true) as normal
			// 2.with parallel mode, we do obj.finalise(true) on dispatcher, not on slot routine
			//   obj.finalise(true) will clear its dirtyStorage, will make prefetch broken.
			if !s.isParallel || !s.parallel.isSlotDB {
				obj.finalise(true) // Prefetch slots in the background
			}
		}
		if _, exist := s.stateObjectsPending[addr]; !exist {
			s.stateObjectsPending[addr] = struct{}{}
		}
		if _, exist := s.stateObjectsDirty[addr]; !exist {
			s.stateObjectsDirty[addr] = struct{}{}
			// At this point, also ship the address off to the precacher. The precacher
			// will start loading tries, and when the change is eventually committed,
			// the commit-phase will be a lot faster
			addressesToPrefetch = append(addressesToPrefetch, common.CopyBytes(addr[:])) // Copy needed for closure
		}
	}
	if s.prefetcher != nil && len(addressesToPrefetch) > 0 {
		s.prefetcher.prefetch(s.originalRoot, addressesToPrefetch, emptyAddr)
	}
	// Invalidate journal because reverting across transactions is not allowed.
	s.clearJournalAndRefund()
}

// IntermediateRoot computes the current root hash of the state trie.
// It is called in between transactions to get the root hash that
// goes into transaction receipts.
func (s *StateDB) IntermediateRoot(deleteEmptyObjects bool) common.Hash {
	if s.lightProcessed {
		s.StopPrefetcher()
		return s.trie.Hash()
	}
	// Finalise all the dirty storage states and write them into the tries
	s.Finalise(deleteEmptyObjects)
	s.AccountsIntermediateRoot()
	return s.StateIntermediateRoot()
}

func (s *StateDB) AccountsIntermediateRoot() {
	tasks := make(chan func())
	finishCh := make(chan struct{})
	defer close(finishCh)
	wg := sync.WaitGroup{}
	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			for {
				select {
				case task := <-tasks:
					task()
				case <-finishCh:
					return
				}
			}
		}()
	}

	// Although naively it makes sense to retrieve the account trie and then do
	// the contract storage and account updates sequentially, that short circuits
	// the account prefetcher. Instead, let's process all the storage updates
	// first, giving the account prefeches just a few more milliseconds of time
	// to pull useful data from disk.
	for addr := range s.stateObjectsPending {
		if obj, _ := s.getStateObjectFromStateObjects(addr); !obj.deleted {
			wg.Add(1)
			tasks <- func() {
				obj.updateRoot(s.db)
				// If state snapshotting is active, cache the data til commit. Note, this
				// update mechanism is not symmetric to the deletion, because whereas it is
				// enough to track account updates at commit time, deletions need tracking
				// at transaction boundary level to ensure we capture state clearing.
				if s.snap != nil && !obj.deleted {
					s.snapMux.Lock()
					// It is possible to add unnecessary change, but it is fine.
					s.snapAccounts[obj.address] = snapshot.SlimAccountRLP(obj.data.Nonce, obj.data.Balance, obj.data.Root, obj.data.CodeHash)
					s.snapMux.Unlock()
				}
				data, err := rlp.EncodeToBytes(obj)
				if err != nil {
					panic(fmt.Errorf("can't encode object at %x: %v", addr[:], err))
				}
				obj.encodeData = data
				wg.Done()
			}
		}
	}
	wg.Wait()
}

func (s *StateDB) StateIntermediateRoot() common.Hash {
	// If there was a trie prefetcher operating, it gets aborted and irrevocably
	// modified after we start retrieving tries. Remove it from the statedb after
	// this round of use.
	//
	// This is weird pre-byzantium since the first tx runs with a prefetcher and
	// the remainder without, but pre-byzantium even the initial prefetcher is
	// useless, so no sleep lost.
	prefetcher := s.prefetcher
	defer func() {
		s.prefetcherLock.Lock()
		if s.prefetcher != nil {
			s.prefetcher.close()
			s.prefetcher = nil
		}
		// try not use defer inside defer
		s.prefetcherLock.Unlock()
	}()

	// Now we're about to start to write changes to the trie. The trie is so far
	// _untouched_. We can check with the prefetcher, if it can give us a trie
	// which has the same root, but also has some content loaded into it.
	if prefetcher != nil {
		if trie := prefetcher.trie(s.originalRoot); trie != nil {
			s.trie = trie
		}
	}
	if s.trie == nil {
		tr, err := s.db.OpenTrie(s.originalRoot)
		if err != nil {
			panic(fmt.Sprintf("Failed to open trie tree %s", s.originalRoot))
		}
		s.trie = tr
	}
	usedAddrs := make([][]byte, 0, len(s.stateObjectsPending))
	for addr := range s.stateObjectsPending {
		if obj, _ := s.getStateObjectFromStateObjects(addr); obj.deleted {
			s.deleteStateObject(obj)
		} else {
			s.updateStateObject(obj)
		}
		usedAddrs = append(usedAddrs, common.CopyBytes(addr[:])) // Copy needed for closure
	}
	if prefetcher != nil {
		prefetcher.used(s.originalRoot, usedAddrs)
	}
	if len(s.stateObjectsPending) > 0 {
		s.stateObjectsPending = make(map[common.Address]struct{})
	}
	// Track the amount of time wasted on hashing the account trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.AccountHashes += time.Since(start) }(time.Now())
	}
	root := s.trie.Hash()
	return root
}

// Prepare sets the current transaction hash and index and block hash which is
// used when the EVM emits new state logs.
func (s *StateDB) Prepare(thash, bhash common.Hash, ti int) {
	s.thash = thash
	s.bhash = bhash
	s.txIndex = ti
	s.accessList = nil
}

func (s *StateDB) clearJournalAndRefund() {
	if len(s.journal.entries) > 0 {
		s.journal = newJournal()
		s.refund = 0
	}
	s.validRevisions = s.validRevisions[:0] // Snapshots can be created without journal entires
}

func (s *StateDB) LightCommit() (common.Hash, *types.DiffLayer, error) {
	codeWriter := s.db.TrieDB().DiskDB().NewBatch()

	// light process already verified it, expectedRoot is trustworthy.
	root := s.expectedRoot

	commitFuncs := []func() error{
		func() error {
			for codeHash, code := range s.diffCode {
				rawdb.WriteCode(codeWriter, codeHash, code)
				if codeWriter.ValueSize() >= ethdb.IdealBatchSize {
					if err := codeWriter.Write(); err != nil {
						return err
					}
					codeWriter.Reset()
				}
			}
			if codeWriter.ValueSize() > 0 {
				if err := codeWriter.Write(); err != nil {
					return err
				}
			}
			return nil
		},
		func() error {
			tasks := make(chan func())
			taskResults := make(chan error, len(s.diffTries))
			tasksNum := 0
			finishCh := make(chan struct{})
			defer close(finishCh)
			threads := gopool.Threads(len(s.diffTries))

			for i := 0; i < threads; i++ {
				go func() {
					for {
						select {
						case task := <-tasks:
							task()
						case <-finishCh:
							return
						}
					}
				}()
			}

			for account, diff := range s.diffTries {
				tmpAccount := account
				tmpDiff := diff
				tasks <- func() {
					root, err := tmpDiff.Commit(nil)
					if err != nil {
						taskResults <- err
						return
					}
					s.db.CacheStorage(crypto.Keccak256Hash(tmpAccount[:]), root, tmpDiff)
					taskResults <- nil
				}
				tasksNum++
			}

			for i := 0; i < tasksNum; i++ {
				err := <-taskResults
				if err != nil {
					return err
				}
			}

			// commit account trie
			var account Account
			root, err := s.trie.Commit(func(_ [][]byte, _ []byte, leaf []byte, parent common.Hash) error {
				if err := rlp.DecodeBytes(leaf, &account); err != nil {
					return nil
				}
				if account.Root != emptyRoot {
					s.db.TrieDB().Reference(account.Root, parent)
				}
				return nil
			})
			if err != nil {
				return err
			}
			if root != emptyRoot {
				s.db.CacheAccount(root, s.trie)
			}
			return nil
		},
		func() error {
			if s.snap != nil {
				if metrics.EnabledExpensive {
					defer func(start time.Time) { s.SnapshotCommits += time.Since(start) }(time.Now())
				}
				// Only update if there's a state transition (skip empty Clique blocks)
				if parent := s.snap.Root(); parent != root {
					// for light commit, always do sync commit
					if err := s.snaps.Update(root, parent, s.snapDestructs, s.snapAccounts, s.snapStorage, nil); err != nil {
						log.Warn("Failed to update snapshot tree", "from", parent, "to", root, "err", err)
					}
					// Keep n diff layers in the memory
					// - head layer is paired with HEAD state
					// - head-1 layer is paired with HEAD-1 state
					// - head-(n-1) layer(bottom-most diff layer) is paired with HEAD-(n-1)state
					if err := s.snaps.Cap(root, s.snaps.CapLimit()); err != nil {
						log.Warn("Failed to cap snapshot tree", "root", root, "layers", s.snaps.CapLimit(), "err", err)
					}
				}
			}
			return nil
		},
	}
	commitRes := make(chan error, len(commitFuncs))
	for _, f := range commitFuncs {
		tmpFunc := f
		go func() {
			commitRes <- tmpFunc()
		}()
	}
	for i := 0; i < len(commitFuncs); i++ {
		r := <-commitRes
		if r != nil {
			return common.Hash{}, nil, r
		}
	}
	s.snap, s.snapDestructs, s.snapAccounts, s.snapStorage = nil, nil, nil, nil
	s.diffTries, s.diffCode = nil, nil
	return root, s.diffLayer, nil
}

// Commit writes the state to the underlying in-memory trie database.
func (s *StateDB) Commit(failPostCommitFunc func(), postCommitFuncs ...func() error) (common.Hash, *types.DiffLayer, error) {
	if s.dbErr != nil {
		return common.Hash{}, nil, fmt.Errorf("commit aborted due to earlier error: %v", s.dbErr)
	}
	// Finalize any pending changes and merge everything into the tries
	if s.lightProcessed {
		root, diff, err := s.LightCommit()
		if err != nil {
			return root, diff, err
		}
		for _, postFunc := range postCommitFuncs {
			err = postFunc()
			if err != nil {
				return root, diff, err
			}
		}
		return root, diff, nil
	}
	var diffLayer *types.DiffLayer
	var verified chan struct{}
	var snapUpdated chan struct{}
	if s.snap != nil {
		diffLayer = &types.DiffLayer{}
	}
	if s.pipeCommit {
		// async commit the MPT
		verified = make(chan struct{})
		snapUpdated = make(chan struct{})
	}

	commmitTrie := func() error {
		commitErr := func() error {
			if s.stateRoot = s.StateIntermediateRoot(); s.fullProcessed && s.expectedRoot != s.stateRoot {
				return fmt.Errorf("invalid merkle root (remote: %x local: %x)", s.expectedRoot, s.stateRoot)
			}
			tasks := make(chan func())
			taskResults := make(chan error, len(s.stateObjectsDirty))
			tasksNum := 0
			finishCh := make(chan struct{})

			threads := gopool.Threads(len(s.stateObjectsDirty))
			wg := sync.WaitGroup{}
			for i := 0; i < threads; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case task := <-tasks:
							task()
						case <-finishCh:
							return
						}
					}
				}()
			}

			if s.snap != nil {
				for addr := range s.stateObjectsDirty {
					if obj, _ := s.getStateObjectFromStateObjects(addr); !obj.deleted {
						if obj.code != nil && obj.dirtyCode {
							diffLayer.Codes = append(diffLayer.Codes, types.DiffCode{
								Hash: common.BytesToHash(obj.CodeHash()),
								Code: obj.code,
							})
						}
					}
				}
			}

			for addr := range s.stateObjectsDirty {
				if obj, _ := s.getStateObjectFromStateObjects(addr); !obj.deleted {
					// Write any contract code associated with the state object
					tasks <- func() {
						// Write any storage changes in the state object to its storage trie
						if err := obj.CommitTrie(s.db); err != nil {
							taskResults <- err
						}
						taskResults <- nil
					}
					tasksNum++
				}
			}

			for i := 0; i < tasksNum; i++ {
				err := <-taskResults
				if err != nil {
					close(finishCh)
					return err
				}
			}
			close(finishCh)

			// The onleaf func is called _serially_, so we can reuse the same account
			// for unmarshalling every time.
			var account Account
			root, err := s.trie.Commit(func(_ [][]byte, _ []byte, leaf []byte, parent common.Hash) error {
				if err := rlp.DecodeBytes(leaf, &account); err != nil {
					return nil
				}
				if account.Root != emptyRoot {
					s.db.TrieDB().Reference(account.Root, parent)
				}
				return nil
			})
			if err != nil {
				return err
			}
			if root != emptyRoot {
				s.db.CacheAccount(root, s.trie)
			}
			for _, postFunc := range postCommitFuncs {
				err = postFunc()
				if err != nil {
					return err
				}
			}
			wg.Wait()
			return nil
		}()

		if s.pipeCommit {
			if commitErr == nil {
				<-snapUpdated
				s.snaps.Snapshot(s.stateRoot).MarkValid()
			} else {
				// The blockchain will do the further rewind if write block not finish yet
				if failPostCommitFunc != nil {
					<-snapUpdated
					failPostCommitFunc()
				}
				log.Error("state verification failed", "err", commitErr)
			}
			close(verified)
		}
		return commitErr
	}

	commitFuncs := []func() error{
		func() error {
			codeWriter := s.db.TrieDB().DiskDB().NewBatch()
			for addr := range s.stateObjectsDirty {
				if obj, _ := s.getStateObjectFromStateObjects(addr); !obj.deleted {
					if obj.code != nil && obj.dirtyCode {
						rawdb.WriteCode(codeWriter, common.BytesToHash(obj.CodeHash()), obj.code)
						obj.dirtyCode = false
						if codeWriter.ValueSize() > ethdb.IdealBatchSize {
							if err := codeWriter.Write(); err != nil {
								return err
							}
							codeWriter.Reset()
						}
					}
				}
			}
			if codeWriter.ValueSize() > 0 {
				if err := codeWriter.Write(); err != nil {
					log.Crit("Failed to commit dirty codes", "error", err)
					return err
				}
			}
			return nil
		},
		func() error {
			// If snapshotting is enabled, update the snapshot tree with this new version
			if s.snap != nil {
				if metrics.EnabledExpensive {
					defer func(start time.Time) { s.SnapshotCommits += time.Since(start) }(time.Now())
				}
				if s.pipeCommit {
					defer close(snapUpdated)
				}
				// Only update if there's a state transition (skip empty Clique blocks)
				if parent := s.snap.Root(); parent != s.expectedRoot {
					if err := s.snaps.Update(s.expectedRoot, parent, s.snapDestructs, s.snapAccounts, s.snapStorage, verified); err != nil {
						log.Warn("Failed to update snapshot tree", "from", parent, "to", s.expectedRoot, "err", err)
					}
					// Keep n diff layers in the memory
					// - head layer is paired with HEAD state
					// - head-1 layer is paired with HEAD-1 state
					// - head-(n-1) layer(bottom-most diff layer) is paired with HEAD-(n-1)state
					go func() {
						if err := s.snaps.Cap(s.expectedRoot, s.snaps.CapLimit()); err != nil {
							log.Warn("Failed to cap snapshot tree", "root", s.expectedRoot, "layers", s.snaps.CapLimit(), "err", err)
						}
					}()
				}
			}
			return nil
		},
		func() error {
			if s.snap != nil {
				diffLayer.Destructs, diffLayer.Accounts, diffLayer.Storages = s.SnapToDiffLayer()
			}
			return nil
		},
	}
	if s.pipeCommit {
		go commmitTrie()
	} else {
		commitFuncs = append(commitFuncs, commmitTrie)
	}
	commitRes := make(chan error, len(commitFuncs))
	for _, f := range commitFuncs {
		tmpFunc := f
		go func() {
			commitRes <- tmpFunc()
		}()
	}
	for i := 0; i < len(commitFuncs); i++ {
		r := <-commitRes
		if r != nil {
			return common.Hash{}, nil, r
		}
	}
	root := s.stateRoot
	if s.pipeCommit {
		root = s.expectedRoot
	}

	return root, diffLayer, nil
}

func (s *StateDB) DiffLayerToSnap(diffLayer *types.DiffLayer) (map[common.Address]struct{}, map[common.Address][]byte, map[common.Address]map[string][]byte, error) {
	snapDestructs := make(map[common.Address]struct{})
	snapAccounts := make(map[common.Address][]byte)
	snapStorage := make(map[common.Address]map[string][]byte)

	for _, des := range diffLayer.Destructs {
		snapDestructs[des] = struct{}{}
	}
	for _, account := range diffLayer.Accounts {
		snapAccounts[account.Account] = account.Blob
	}
	for _, storage := range diffLayer.Storages {
		// should never happen
		if len(storage.Keys) != len(storage.Vals) {
			return nil, nil, nil, errors.New("invalid diffLayer: length of keys and values mismatch")
		}
		snapStorage[storage.Account] = make(map[string][]byte, len(storage.Keys))
		n := len(storage.Keys)
		for i := 0; i < n; i++ {
			snapStorage[storage.Account][storage.Keys[i]] = storage.Vals[i]
		}
	}
	return snapDestructs, snapAccounts, snapStorage, nil
}

func (s *StateDB) SnapToDiffLayer() ([]common.Address, []types.DiffAccount, []types.DiffStorage) {
	destructs := make([]common.Address, 0, len(s.snapDestructs))
	for account := range s.snapDestructs {
		destructs = append(destructs, account)
	}
	accounts := make([]types.DiffAccount, 0, len(s.snapAccounts))
	for accountHash, account := range s.snapAccounts {
		accounts = append(accounts, types.DiffAccount{
			Account: accountHash,
			Blob:    account,
		})
	}
	storages := make([]types.DiffStorage, 0, len(s.snapStorage))
	for accountHash, storage := range s.snapStorage {
		keys := make([]string, 0, len(storage))
		values := make([][]byte, 0, len(storage))
		for k, v := range storage {
			keys = append(keys, k)
			values = append(values, v)
		}
		storages = append(storages, types.DiffStorage{
			Account: accountHash,
			Keys:    keys,
			Vals:    values,
		})
	}
	return destructs, accounts, storages
}

// PrepareAccessList handles the preparatory steps for executing a state transition with
// regards to both EIP-2929 and EIP-2930:
//
// - Add sender to access list (2929)
// - Add destination to access list (2929)
// - Add precompiles to access list (2929)
// - Add the contents of the optional tx access list (2930)
//
// This method should only be called if Yolov3/Berlin/2929+2930 is applicable at the current number.
func (s *StateDB) PrepareAccessList(sender common.Address, dst *common.Address, precompiles []common.Address, list types.AccessList) {
	s.AddAddressToAccessList(sender)
	if dst != nil {
		s.AddAddressToAccessList(*dst)
		// If it's a create-tx, the destination will be added inside evm.create
	}
	for _, addr := range precompiles {
		s.AddAddressToAccessList(addr)
	}
	for _, el := range list {
		s.AddAddressToAccessList(el.Address)
		for _, key := range el.StorageKeys {
			s.AddSlotToAccessList(el.Address, key)
		}
	}
}

// AddAddressToAccessList adds the given address to the access list
func (s *StateDB) AddAddressToAccessList(addr common.Address) {
	if s.accessList == nil {
		s.accessList = newAccessList()
	}
	if s.accessList.AddAddress(addr) {
		s.journal.append(accessListAddAccountChange{&addr})
	}
}

// AddSlotToAccessList adds the given (address, slot)-tuple to the access list
func (s *StateDB) AddSlotToAccessList(addr common.Address, slot common.Hash) {
	if s.accessList == nil {
		s.accessList = newAccessList()
	}
	addrMod, slotMod := s.accessList.AddSlot(addr, slot)
	if addrMod {
		// In practice, this should not happen, since there is no way to enter the
		// scope of 'address' without having the 'address' become already added
		// to the access list (via call-variant, create, etc).
		// Better safe than sorry, though
		s.journal.append(accessListAddAccountChange{&addr})
	}
	if slotMod {
		s.journal.append(accessListAddSlotChange{
			address: &addr,
			slot:    &slot,
		})
	}
}

// AddressInAccessList returns true if the given address is in the access list.
func (s *StateDB) AddressInAccessList(addr common.Address) bool {
	if s.accessList == nil {
		return false
	}
	return s.accessList.ContainsAddress(addr)
}

// SlotInAccessList returns true if the given (address, slot)-tuple is in the access list.
func (s *StateDB) SlotInAccessList(addr common.Address, slot common.Hash) (addressPresent bool, slotPresent bool) {
	if s.accessList == nil {
		return false, false
	}
	return s.accessList.Contains(addr, slot)
}

func (s *StateDB) GetDirtyAccounts() []common.Address {
	accounts := make([]common.Address, 0, len(s.stateObjectsDirty))
	for account := range s.stateObjectsDirty {
		accounts = append(accounts, account)
	}
	return accounts
}
