// Copyright 2018 The go-ethereum Authors
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
package votemanager

import (
	"errors"
	"sync"

	mapset "github.com/deckarep/golang-set"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	maxVoteAmountForSingleBlock = 21
	itemsAmountInPriorityQueue  = 1000
	lowerLimitOfVoteBlockNumber = 256
	upperLimitOfVoteBlockNumber = 11

	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10
)

var InvalidVote = errors.New("Invalid Vote")

type blockChain interface {
	CurrentBlock() *types.Block
	GetBlock(hash common.Hash, number uint64) *types.Block
	StateAt(root common.Hash) (*state.StateDB, error)
	SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription
	GetHeader(hash common.Hash, number uint64) *types.Header
}

type BLS interface {
	Verify(vote *types.VoteRecord) bool
	Sign(vote *types.VoteRecord) bool
}

type VoteBox struct {
	blockNumber  uint64
	voteMessages []*types.VoteRecord
}

type VotesPool struct {
	chain       blockChain
	chainconfig *params.ChainConfig
	mu          sync.RWMutex

	votesFeed event.Feed
	scope     event.SubscriptionScope

	isDuplicateVote mapset.Set

	curVotes    map[common.Hash]*VoteBox
	futureVotes map[common.Hash]*VoteBox

	curBlockPq    blockPriorityQueue
	futureBlockPq blockPriorityQueue

	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription

	blockNumberForPrune chan uint64
	bls                 BLS
	wg                  sync.WaitGroup // tracks loop
}

type blockPriorityQueue []*types.VoteData

func NewVotesPool(chainconfig *params.ChainConfig, chain blockChain) *VotesPool {

	vp := &VotesPool{
		chain:               chain,
		chainconfig:         chainconfig,
		isDuplicateVote:     mapset.NewSet(),
		curVotes:            make(map[common.Hash]*VoteBox),
		futureVotes:         make(map[common.Hash]*VoteBox),
		curBlockPq:          make([]*types.VoteData, itemsAmountInPriorityQueue),
		futureBlockPq:       make([]*types.VoteData, itemsAmountInPriorityQueue),
		chainHeadCh:         make(chan core.ChainHeadEvent, chainHeadChanSize),
		blockNumberForPrune: make(chan uint64, chainHeadChanSize),
	}

	// Subscribe events from blockchain and start the main event loop.
	vp.chainHeadSub = vp.chain.SubscribeChainHeadEvent(vp.chainHeadCh)
	vp.wg.Add(1)
	go vp.loop()

	vp.wg.Add(1)
	go vp.votePoolPruner()

	return vp
}

// loop is the vote pool's main even loop, waiting for and reacting to outside blockchain events.
func (vp *VotesPool) loop() {
	defer vp.wg.Done()

	for {
		select {
		// Handle ChainHeadEvent
		case ev := <-vp.chainHeadCh:
			if ev.Block != nil {
				curBlockNumber := ev.Block.NumberU64()
				vp.blockNumberForPrune <- curBlockNumber

			}
		case <-vp.chainHeadSub.Err():
			return
		}
	}

}

func (vp *VotesPool) PutVote(voteMessage *types.VoteRecord) (bool, error) {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	voteBlockNumber := voteMessage.Data.BlockNumber
	voteBlockHash := voteMessage.Data.BlockHash
	headNumber := vp.chain.CurrentBlock().NumberU64()

	if ok, err := vp.isValid(voteMessage, headNumber, voteBlockNumber); err == nil {
		if !ok {
			return false, InvalidVote
		}
	} else {
		return false, err
	}

	voteData := &types.VoteData{
		BlockNumber: voteBlockNumber,
		BlockHash:   voteBlockHash,
	}

	if voteBlockNumber > headNumber {
		if err := putInMap(&vp.futureVotes, voteBlockHash, voteBlockNumber, voteMessage); err == nil {
			vp.futureBlockPq.Push(voteData)

		} else {
			return false, err
		}

	} else {
		if !vp.bls.Verify(voteMessage) {
			return false, nil
		}

		if err := putInMap(&vp.curVotes, voteBlockHash, voteBlockNumber, voteMessage); err == nil {
			vp.curBlockPq.Push(voteData)

		} else {
			return false, err
		}

	}
	vp.votesFeed.Send(voteMessage)
	return true, nil
}

func (vp *VotesPool) SubscribeNewVotesEvent(ch chan<- []*types.VoteRecord) event.Subscription {
	return vp.scope.Track(vp.votesFeed.Subscribe(ch))
}

func putInMap(m *map[common.Hash]*VoteBox, voteBlockHash common.Hash, voteBlockNumber uint64, voteMessage *types.VoteRecord) error {
	if voteRecords, ok := (*m)[voteBlockHash]; ok {
		if len(voteRecords.voteMessages) == maxVoteAmountForSingleBlock {
			return InvalidVote
		} else {
			voteRecords.voteMessages = append(voteRecords.voteMessages, voteMessage)
		}
	} else {
		vBox := &VoteBox{
			blockNumber:  voteBlockNumber,
			voteMessages: make([]*types.VoteRecord, 0, maxVoteAmountForSingleBlock),
		}
		(*m)[voteBlockHash] = vBox
	}
	return nil
}

func (vp *VotesPool) transferVotesFromFutureToCur(curBlockNumber uint64) {
	curPq, futurePq := vp.curBlockPq, vp.futureBlockPq
	curVotes, futureVotes := vp.curVotes, vp.futureVotes

	for futurePq[0].BlockNumber <= curBlockNumber {
		blockHash := futurePq[0].BlockHash
		vote := futureVotes[blockHash]
		validVotes := make([]*types.VoteRecord, 0, len(vote.voteMessages))
		for _, v := range vote.voteMessages {
			// Verify the future vote.
			if vp.bls.Verify(v) {
				validVotes = append(validVotes, v)
			}
		}
		vote.voteMessages = validVotes
		curVotes[blockHash] = vote
		voteData := futurePq.Pop()
		curPq.Push(voteData)
		delete(futureVotes, blockHash)
	}
}

// Prune duplicationSet, priorityQueue and Map of curVotes.
func (vp *VotesPool) votePoolPruner() {
	defer vp.wg.Done()

	for curBlockNumber := range vp.blockNumberForPrune {
		vp.mu.Lock()
		curBlockPq := vp.curBlockPq
		curVotes := vp.curVotes

		for curBlockPq[0].BlockNumber < curBlockNumber-lowerLimitOfVoteBlockNumber {
			blockHash := curBlockPq[0].BlockHash
			// Prune priorityQueue.
			curBlockPq.Pop()
			voteRecords := curVotes[blockHash].voteMessages

			// Prune duplicationSet.
			for _, voteRecord := range voteRecords {
				vote, err := rlp.EncodeToBytes(voteRecord)
				if err != nil {
					log.Warn("Failed to Encode voteRecord", "err", err)
				}
				vp.isDuplicateVote.Remove(vote)
			}
			// Prune curVotes Map.
			delete(curVotes, blockHash)
			vp.mu.Unlock()
		}

		vp.transferVotesFromFutureToCur(curBlockNumber)
	}

}

// Get votes as batch.
func (vp *VotesPool) GetVotes() []*types.VoteRecord {
	vp.mu.RLock()
	defer vp.mu.Unlock()

	allVotes := make([]*types.VoteRecord, 0)
	curVotes := vp.curVotes
	for _, vBox := range curVotes {
		allVotes = append(allVotes, vBox.voteMessages...)
	}
	futureVotes := vp.futureVotes
	for _, vBox := range futureVotes {
		allVotes = append(allVotes, vBox.voteMessages...)
	}
	return allVotes
}

func (vp *VotesPool) FetchAvailableVotes(blockHash common.Hash) ([]*types.VoteRecord, bool) {
	vp.mu.RLock()
	defer vp.mu.Unlock()
	if vote, ok := vp.curVotes[blockHash]; ok && len(vote.voteMessages) >= maxVoteAmountForSingleBlock*3/4 {
		return vote.voteMessages, true
	}
	return nil, false
}

func (vp *VotesPool) isValid(voteMessage *types.VoteRecord, headNumber, voteBlockNumber uint64) (bool, error) {
	// Check duplicate voteMessage firstly.
	vote, err := rlp.EncodeToBytes(voteMessage)
	if err != nil {
		return false, err
	}

	if vp.isDuplicateVote.Contains(vote) {
		return false, nil
	}
	vp.isDuplicateVote.Add(vote)

	// Make sure in the range currentHeight-256~currentHeight+11.
	if voteBlockNumber < headNumber-lowerLimitOfVoteBlockNumber || voteBlockNumber > headNumber+upperLimitOfVoteBlockNumber {
		return false, nil
	}
	return true, nil
}

func (pq blockPriorityQueue) Less(i, j int) bool {
	return pq[i].BlockNumber < pq[j].BlockNumber
}

func (pq blockPriorityQueue) Len() int {
	return len(pq)
}

func (pq blockPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *blockPriorityQueue) Push(vote interface{}) {
	curVote := vote.(*types.VoteData)
	*pq = append(*pq, curVote)
}

func (pq *blockPriorityQueue) Pop() interface{} {
	tmp := *pq
	l := len(tmp)
	var res interface{} = tmp[l-1]
	*pq = tmp[:l-1]
	return res
}
