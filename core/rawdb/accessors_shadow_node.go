package rawdb

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

func DeleteShadowNodeSnapshotJournal(db ethdb.KeyValueWriter) {
	if err := db.Delete(shadowNodeSnapshotJournalKey); err != nil {
		log.Crit("Failed to remove snapshot journal", "err", err)
	}
}

func ReadShadowNodeSnapshotJournal(db ethdb.KeyValueReader) []byte {
	data, _ := db.Get(shadowNodeSnapshotJournalKey)
	return data
}

func WriteShadowNodeSnapshotJournal(db ethdb.KeyValueWriter, journal []byte) {
	if err := db.Put(shadowNodeSnapshotJournalKey, journal); err != nil {
		log.Crit("Failed to store snapshot journal", "err", err)
	}
}

func ReadShadowNodePlainStateMeta(db ethdb.KeyValueReader) []byte {
	data, _ := db.Get(shadowNodePlainStateMeta)
	return data
}

func WriteShadowNodePlainStateMeta(db ethdb.KeyValueWriter, val []byte) error {
	return db.Put(shadowNodePlainStateMeta, val)
}

func ReadShadowNodeHistory(db ethdb.KeyValueReader, addr common.Hash, path string, number uint64) []byte {
	val, _ := db.Get(shadowNodeHistoryKey(addr, path, number))
	return val
}

func WriteShadowNodeHistory(db ethdb.KeyValueWriter, addr common.Hash, path string, number uint64, val []byte) error {
	return db.Put(shadowNodeHistoryKey(addr, path, number), val)
}

func ReadShadowNodeChangeSet(db ethdb.KeyValueReader, addr common.Hash, number uint64) []byte {
	val, _ := db.Get(shadowNodeChangeSetKey(addr, number))
	return val
}

func WriteShadowNodeChangeSet(db ethdb.KeyValueWriter, addr common.Hash, number uint64, val []byte) error {
	return db.Put(shadowNodeChangeSetKey(addr, number), val)
}

func ReadShadowNodePlainState(db ethdb.KeyValueReader, addr common.Hash, path string) []byte {
	val, _ := db.Get(shadowNodePlainStateKey(addr, path))
	return val
}

func WriteShadowNodePlainState(db ethdb.KeyValueWriter, addr common.Hash, path string, val []byte) error {
	return db.Put(shadowNodePlainStateKey(addr, path), val)
}

func DeleteShadowNodePlainState(db ethdb.KeyValueWriter, addr common.Hash, path string) error {
	return db.Delete(shadowNodePlainStateKey(addr, path))
}

func shadowNodeChangeSetKey(addr common.Hash, number uint64) []byte {
	key := make([]byte, len(ShadowNodeChangeSetPrefix)+8+len(addr))
	copy(key[:], ShadowNodeHistoryPrefix)
	binary.BigEndian.PutUint64(key[len(ShadowNodeHistoryPrefix):], number)
	copy(key[len(ShadowNodeHistoryPrefix)+8:], addr.Bytes())
	return key
}

func shadowNodeHistoryKey(addr common.Hash, path string, number uint64) []byte {
	key := make([]byte, len(ShadowNodeHistoryPrefix)+len(addr)+len(path)+8)
	copy(key[:], ShadowNodeHistoryPrefix)
	copy(key[len(ShadowNodeHistoryPrefix):], addr.Bytes())
	copy(key[len(ShadowNodeHistoryPrefix)+len(addr):], path)
	binary.BigEndian.PutUint64(key[len(key)-8:], number)
	return key
}

func shadowNodePlainStateKey(addr common.Hash, path string) []byte {
	key := make([]byte, len(ShadowNodePlainStatePrefix)+len(addr)+len(path))
	copy(key[:], ShadowNodeHistoryPrefix)
	copy(key[len(ShadowNodeHistoryPrefix):], addr.Bytes())
	copy(key[len(ShadowNodeHistoryPrefix)+len(addr):], path)
	return key
}
