package rawdb

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

func DeleteEpochMetaSnapshotJournal(db ethdb.KeyValueWriter) {
	if err := db.Delete(epochMetaSnapshotJournalKey); err != nil {
		log.Crit("Failed to remove snapshot journal", "err", err)
	}
}

func ReadEpochMetaSnapshotJournal(db ethdb.KeyValueReader) []byte {
	data, _ := db.Get(epochMetaSnapshotJournalKey)
	return data
}

func WriteEpochMetaSnapshotJournal(db ethdb.KeyValueWriter, journal []byte) {
	if err := db.Put(epochMetaSnapshotJournalKey, journal); err != nil {
		log.Crit("Failed to store snapshot journal", "err", err)
	}
}

func ReadEpochMetaPlainStateMeta(db ethdb.KeyValueReader) []byte {
	data, _ := db.Get(epochMetaPlainStateMeta)
	return data
}

func WriteEpochMetaPlainStateMeta(db ethdb.KeyValueWriter, val []byte) error {
	return db.Put(epochMetaPlainStateMeta, val)
}

func ReadEpochMetaPlainState(db ethdb.KeyValueReader, addr common.Hash, path string) []byte {
	val, _ := db.Get(epochMetaPlainStateKey(addr, path))
	return val
}

func WriteEpochMetaPlainState(db ethdb.KeyValueWriter, addr common.Hash, path string, val []byte) error {
	return db.Put(epochMetaPlainStateKey(addr, path), val)
}

func DeleteEpochMetaPlainState(db ethdb.KeyValueWriter, addr common.Hash, path string) error {
	return db.Delete(epochMetaPlainStateKey(addr, path))
}

func epochMetaPlainStateKey(addr common.Hash, path string) []byte {
	key := make([]byte, len(EpochMetaPlainStatePrefix)+len(addr)+len(path))
	copy(key[:], EpochMetaPlainStatePrefix)
	copy(key[len(EpochMetaPlainStatePrefix):], addr.Bytes())
	copy(key[len(EpochMetaPlainStatePrefix)+len(addr):], path)
	return key
}
