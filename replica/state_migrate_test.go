// SPDX-FileCopyrightText: Copyright (C) 2026 Katzenpost Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/linxGnu/grocksdb"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/config"
)

// seedLegacyRocksDB writes a RocksDB database at dir/replica.db holding the
// supplied box records (in the default column family) and a rebalance
// fingerprint (in the metadata column family), then closes it. This mimics a
// pre-migration on-disk state so the migration path can be exercised.
func seedLegacyRocksDB(t *testing.T, dir string, boxes map[uint64][bacap.BoxIDSize]byte, fp [32]byte) map[string][]byte {
	t.Helper()
	path := filepath.Join(dir, "replica.db")

	opts := grocksdb.NewDefaultOptions()
	defer opts.Destroy()
	opts.SetCreateIfMissing(true)
	opts.SetCreateIfMissingColumnFamilies(true)
	cfOpts := []*grocksdb.Options{opts, opts}
	db, handles, err := grocksdb.OpenDbColumnFamilies(opts, path, []string{defaultCFName, metadataCFName}, cfOpts)
	require.NoError(t, err)
	defer db.Close()

	wo := grocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()

	written := make(map[string][]byte)
	for ep, boxID := range boxes {
		box := &pigeonhole.Box{
			BoxID:      boxID,
			PayloadLen: uint32(len(boxID)),
			Payload:    boxID[:],
		}
		copy(box.Signature[:], boxID[:])
		key := boxKey(ep, boxID[:])
		require.NoError(t, db.Put(wo, key, box.Bytes()))
		written[string(key)] = box.Bytes()
	}
	require.NoError(t, db.PutCF(wo, handles[1], lastRebalanceReplicasKey, fp[:]))
	written[string(lastRebalanceReplicasKey)] = fp[:]

	for _, h := range handles {
		h.Destroy()
	}
	return written
}

// newMigrateTestState constructs a minimal state over dataDir WITHOUT opening
// any database, so a test can seed a legacy RocksDB database first and then
// trigger the migration via initDB.
func newMigrateTestState(t *testing.T, dataDir string) *state {
	t.Helper()

	nike := ecdh.Scheme(rand.Reader)
	geom := geo.GeometryFromUserForwardPayloadLength(nike, 1234, true, 5)
	require.NotNil(t, geom)

	pkiScheme := signschemes.ByName("ed25519")
	pk, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	cfg := &config.Config{
		ReplicaNIKEScheme: "X25519",
		DataDir:           dataDir,
		SphinxGeometry:    geom,
		Logging: &config.Logging{
			// FIXME: core/log's disabled backend (discardCloser) embeds a nil
			// io.WriteCloser and never overrides Write, so any Error-level log
			// write through a Disable:true backend panics with a nil dereference.
			// Log to /dev/null instead of Disable:true as a workaround.
			//
			// FIXME: use this log config instead of logging to DevNull if/when
			// core/log stops making Error logs panic:
			//
			//	Disable: true,
			//	Level:   "ERROR",
			Disable: false,
			Level:   "ERROR",
			File:    os.DevNull,
		},
	}
	cfg.SetDefaultTimeouts()

	pkiWorker := &PKIWorker{
		replicas:   replicaCommon.NewReplicaMap(),
		WorkerBase: pki.NewWorkerBase(nil, nil),
	}
	s := &Server{
		identityPublicKey: pk,
		cfg:               cfg,
		PKIWorker:         pkiWorker,
		proxySema:         make(chan struct{}, cfg.ProxyWorkerCount),
	}
	require.NoError(t, s.initLogging())
	pkiWorker.server = s
	s.connector = new(mockConnector)

	return &state{server: s, log: s.LogBackend().GetLogger("state")}
}

func TestMigrateLegacyRocksDB(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-migrate-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	cur := currentReplicaEpoch()
	require.GreaterOrEqual(t, cur, uint64(1))

	var fp [32]byte
	_, err = rand.Reader.Read(fp[:])
	require.NoError(t, err)

	// Three boxes: inside the kept window and one outside it. Migration
	// must copy everything, not just what a read would currently see.
	boxes := make(map[uint64][bacap.BoxIDSize]byte)
	expected := make(map[string][]byte)
	for _, ep := range []uint64{cur, cur - 1, cur + 1} {
		var boxID [bacap.BoxIDSize]byte
		_, err := rand.Reader.Read(boxID[:])
		require.NoError(t, err)
		boxes[ep] = boxID
	}
	for k, v := range seedLegacyRocksDB(t, dataDir, boxes, fp) {
		expected[k] = v
	}

	st := newMigrateTestState(t, dataDir)
	st.initDB()

	// Every record from both column families must be present in Pebble
	// with byte-identical values.
	require.GreaterOrEqual(t, len(expected), 3)
	for key, want := range expected {
		got, closer, err := st.db.Get([]byte(key))
		if err != nil {
			got, closer, err = st.metaDB.Get([]byte(key))
		}
		require.NoError(t, err, "migrated key %x must exist", key)
		require.Equal(t, want, got, "migrated value for key %x", key)
		closer.Close()
	}

	// The rebalance fingerprint must be readable through the metadata path.
	gotFP, ok, err := st.loadLastRebalanceFingerprint()
	require.NoError(t, err)
	require.True(t, ok, "migrated fingerprint must be persisted")
	require.Equal(t, fp, gotFP)

	// A box at the current epoch must be servable end-to-end.
	curBoxID := boxes[cur]
	readBox, err := st.stateHandleReplicaRead(&pigeonhole.ReplicaRead{BoxID: curBoxID})
	require.NoError(t, err)
	require.Equal(t, curBoxID[:], readBox.Payload)
	require.Equal(t, curBoxID, readBox.BoxID)

	// The marker must be set and a second migration must be a no-op.
	done, err := st.legacyMigrationDone()
	require.NoError(t, err)
	require.True(t, done)
	migrated, err := st.migrateLegacyRocksDB()
	require.NoError(t, err)
	require.False(t, migrated, "a second migration must be skipped")

	// Reopening must not re-run the migration (marker persists). Close
	// explicitly: the two Pebble databases are file-locked by the open
	// state, so a second state cannot be opened over them until this one
	// is closed.
	st.Close()
	st2 := newMigrateTestState(t, dataDir)
	st2.initDB()
	defer st2.Close()
	done, err = st2.legacyMigrationDone()
	require.NoError(t, err)
	require.True(t, done)
}

func TestMigrateLegacyRocksDBFreshInstall(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-migrate-fresh-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	st := newMigrateTestState(t, dataDir)
	st.initDB()
	defer st.Close()

	// No legacy RocksDB database was present: migration must be skipped
	// and recorded so later boots do not probe for it again.
	migrated, err := st.migrateLegacyRocksDB()
	require.NoError(t, err)
	require.False(t, migrated)
	done, err := st.legacyMigrationDone()
	require.NoError(t, err)
	require.True(t, done)
}

func TestMigrateLegacyRocksDBChunked(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-migrate-chunked-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	// Seed more records than migrateBatchSize so copyColumnFamily has to
	// flush a full batch mid-iteration, leaving a trailing partial batch.
	const total = migrateBatchSize + 1

	path := filepath.Join(dataDir, "replica.db")
	opts := grocksdb.NewDefaultOptions()
	defer opts.Destroy()
	opts.SetCreateIfMissing(true)
	opts.SetCreateIfMissingColumnFamilies(true)
	cfOpts := []*grocksdb.Options{opts, opts}
	db, handles, err := grocksdb.OpenDbColumnFamilies(opts, path, []string{defaultCFName, metadataCFName}, cfOpts)
	require.NoError(t, err)

	var fp [32]byte
	_, err = rand.Reader.Read(fp[:])
	require.NoError(t, err)

	wb := grocksdb.NewWriteBatch()
	for i := 0; i < total; i++ {
		// Distinct epochs give distinct storage keys.
		key := boxKey(uint64(i), make([]byte, bacap.BoxIDSize))
		wb.Put(key, []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)})
	}
	wb.PutCF(handles[1], lastRebalanceReplicasKey, fp[:])
	wo := grocksdb.NewDefaultWriteOptions()
	require.NoError(t, db.Write(wo, wb))
	wb.Destroy()
	wo.Destroy()
	for _, h := range handles {
		h.Destroy()
	}
	db.Close()

	st := newMigrateTestState(t, dataDir)
	st.initDB()
	defer st.Close()

	// Every record survived the chunked copy byte-for-byte, and the
	// record count is exact.
	count := int64(0)
	it, err := st.db.NewIter(&pebble.IterOptions{})
	require.NoError(t, err)
	for it.First(); it.Valid(); it.Next() {
		i := binary.BigEndian.Uint64(it.Key()[:keyEpochSize])
		want := []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
		require.Equal(t, want, it.Value(), "value for record %d", i)
		count++
	}
	require.NoError(t, it.Error())
	require.NoError(t, it.Close())
	require.Equal(t, int64(total), count)

	// The metadata record and the migration marker survived too.
	fpGot, ok, err := st.loadLastRebalanceFingerprint()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, fp, fpGot)
	done, err := st.legacyMigrationDone()
	require.NoError(t, err)
	require.True(t, done)
}

func TestMigrationVerifyRejectsBadCopy(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-migrate-verify-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	cur := currentReplicaEpoch()
	var boxID [bacap.BoxIDSize]byte
	_, err = rand.Reader.Read(boxID[:])
	require.NoError(t, err)
	seedLegacyRocksDB(t, dataDir, map[uint64][bacap.BoxIDSize]byte{cur: boxID}, [32]byte{})

	st := newMigrateTestState(t, dataDir)
	st.initDB()
	defer st.Close()

	// Reopen the source read-only, as the migration itself does, to drive
	// verifyColumnFamily directly against a tampered target.
	opts := grocksdb.NewDefaultOptions()
	defer opts.Destroy()
	cfOpts := []*grocksdb.Options{opts, opts}
	rocksDB, handles, err := grocksdb.OpenDbForReadOnlyColumnFamilies(
		opts, filepath.Join(dataDir, "replica.db"), []string{defaultCFName, metadataCFName}, cfOpts, false)
	require.NoError(t, err)
	defer func() {
		for _, h := range handles {
			h.Destroy()
		}
		rocksDB.Close()
	}()
	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	key := boxKey(cur, boxID[:])

	// A clean copy verifies and returns the exact source record count.
	count, err := st.verifyColumnFamily(rocksDB, ro, handles[0], st.db)
	require.NoError(t, err)
	require.Equal(t, int64(1), count)

	// A corrupted value must be rejected.
	require.NoError(t, st.db.Set(key, []byte("tampered"), nil))
	_, err = st.verifyColumnFamily(rocksDB, ro, handles[0], st.db)
	require.Error(t, err, "a value mismatch must fail verification")

	// An extra record that has no source must be rejected.
	require.NoError(t, st.db.Set(append(key, 0x00), []byte("extra"), nil))
	_, err = st.verifyColumnFamily(rocksDB, ro, handles[0], st.db)
	require.Error(t, err, "a record absent from the source must fail verification")
}

// TestMigrateLegacyRocksDBInsufficientFreeSpace asserts that the
// migration refuses to start when the data directory cannot hold a
// second copy of the legacy database, and that refusing leaves nothing
// behind: no records copied and no marker, so freeing space and
// restarting retries cleanly against the untouched source.
func TestMigrateLegacyRocksDBInsufficientFreeSpace(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-migrate-nospace-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	cur := currentReplicaEpoch()
	var boxID [bacap.BoxIDSize]byte
	_, err = rand.Reader.Read(boxID[:])
	require.NoError(t, err)
	seedLegacyRocksDB(t, dataDir, map[uint64][bacap.BoxIDSize]byte{cur: boxID}, [32]byte{})

	// One byte free is never enough for a second copy of the source.
	orig := availableBytesFn
	availableBytesFn = func(string) (uint64, bool) { return 1, true }
	defer func() { availableBytesFn = orig }()

	st := newMigrateTestState(t, dataDir)

	// initDB panics on a migration error, so open the Pebble databases
	// directly and drive the migration itself.
	st.db, err = pebble.Open(st.boxesDBPath(), &pebble.Options{})
	require.NoError(t, err)
	st.metaDB, err = pebble.Open(st.metadataDBPath(), &pebble.Options{})
	require.NoError(t, err)
	defer st.Close()

	migrated, err := st.migrateLegacyRocksDB()
	require.Error(t, err)
	require.False(t, migrated)
	require.ErrorContains(t, err, "insufficient free space")

	done, err := st.legacyMigrationDone()
	require.NoError(t, err)
	require.False(t, done, "a refused migration must not record the marker")

	_, closer, err := st.db.Get(boxKey(cur, boxID[:]))
	if err == nil {
		closer.Close()
	}
	require.ErrorIs(t, err, pebble.ErrNotFound,
		"the space check runs before the copy, so no record may have been written")
}

// TestMigrateLegacyRocksDBProceedsWhenFreeSpaceUnknown pins the
// deliberate asymmetry in checkMigrationFreeSpace: an unreadable probe
// is not treated as "no space". availableBytes reports (0, false) on
// Windows, where there is no portable statfs, and refusing to migrate
// there would be worse than migrating unchecked.
func TestMigrateLegacyRocksDBProceedsWhenFreeSpaceUnknown(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-migrate-nospaceprobe-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	cur := currentReplicaEpoch()
	var boxID [bacap.BoxIDSize]byte
	_, err = rand.Reader.Read(boxID[:])
	require.NoError(t, err)
	seedLegacyRocksDB(t, dataDir, map[uint64][bacap.BoxIDSize]byte{cur: boxID}, [32]byte{})

	orig := availableBytesFn
	availableBytesFn = func(string) (uint64, bool) { return 0, false }
	defer func() { availableBytesFn = orig }()

	st := newMigrateTestState(t, dataDir)
	st.initDB() // must not panic
	defer st.Close()

	done, err := st.legacyMigrationDone()
	require.NoError(t, err)
	require.True(t, done)

	readBox, err := st.stateHandleReplicaRead(&pigeonhole.ReplicaRead{BoxID: boxID})
	require.NoError(t, err)
	require.Equal(t, boxID, readBox.BoxID)
}

func TestDirSizeBytes(t *testing.T) {
	dir, err := os.MkdirTemp("", "replica-dirsize-*")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "a"), make([]byte, 100), 0600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sub"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "b"), make([]byte, 200), 0600))

	n, err := dirSizeBytes(dir)
	require.NoError(t, err)
	require.EqualValues(t, 300, n, "sizes must sum across subdirectories")

	// A plain file must size too: a corrupt legacy replica.db can be a
	// regular file rather than a RocksDB directory.
	n, err = dirSizeBytes(filepath.Join(dir, "a"))
	require.NoError(t, err)
	require.EqualValues(t, 100, n)

	_, err = dirSizeBytes(filepath.Join(dir, "does-not-exist"))
	require.Error(t, err)
}

func TestMigrateLegacyRocksDBOpenFailure(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-migrate-open-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	// A corrupt legacy database must abort the migration rather than be
	// silently treated as empty.
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "replica.db"),
		[]byte("this is not a rocksdb database"), 0600))

	st := newMigrateTestState(t, dataDir)

	// Open the Pebble databases without running the migration (initDB
	// would panic on the migration error), then drive the migration
	// directly.
	st.db, err = pebble.Open(st.boxesDBPath(), &pebble.Options{})
	require.NoError(t, err)
	st.metaDB, err = pebble.Open(st.metadataDBPath(), &pebble.Options{})
	require.NoError(t, err)
	defer st.Close()

	_, err = st.migrateLegacyRocksDB()
	require.Error(t, err)

	// No marker was written, so a repaired source could be retried.
	done, err := st.legacyMigrationDone()
	require.NoError(t, err)
	require.False(t, done)
}
