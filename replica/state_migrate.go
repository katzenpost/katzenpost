// SPDX-FileCopyrightText: Copyright (C) 2026 Katzenpost Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cockroachdb/pebble"
	"github.com/linxGnu/grocksdb"
)

// Why Pebble?
//
// The replica's storage used to be a single RocksDB database, accessed through
// the github.com/linxGnu/grocksdb bindings, with two column families. We moved
// it to two Pebble databases to shed the dependency on those bindings: they do
// not yet support the latest RocksDB releases (11.x), so we were pinned to an
// older RocksDB and a cgo toolchain just to build the storage. Pebble is pure
// Go and is more actively maintained.
//
// Pebble does not support RocksDB column families and cannot read a database
// that uses them, so our legacy database (which does) has to be read through
// grocksdb: the switch is a one-time, marker-gated migration. This file is the
// only code that still touches RocksDB; it reads the legacy database read-only
// and copies its two column families into two Pebble databases:
//
//   - <DataDir>/replica-boxes.db     — box records (was the "default" CF)
//   - <DataDir>/replica-metadata.db  — bookkeeping (was the "metadata" CF)
//
// The migration commits in batches, then re-reads every record from the
// Pebble databases and compares it byte-for-byte against the RocksDB source
// (plus a record count) before writing the marker in s.metaDB. The marker
// makes the migration idempotent: a failure mid-migration leaves no marker, so
// the next boot re-runs it against the untouched source.
//
// Incidental improvements that came with the move:
//
//   - Durability. Pebble's nil WriteOptions mean Sync:true, so every
//     acknowledged write (box writes, tombstones, the rebalance fingerprint,
//     migration batches and marker) fsyncs the WAL and now survives a power
//     loss. The old RocksDB code used the non-sync default. Paths that want
//     the old throughput back can pass pebble.NoSync or throttle syncs with
//     Options.WALMinSyncInterval.
//
//   - Honest disk-pressure accounting. dbOnDiskBytes now sums the Pebble
//     DiskSpaceUsage metrics, which count the true on-disk footprint (WAL,
//     obsolete/zombie tables, manifest) instead of RocksDB's
//     total-sst-files-size (live SSTs only). For a "reject writes before the
//     disk fills" guard that errs safe.
//
//   - Simpler iterator code. Pebble manages the memory behind the keys and
//     values it hands out, so the pervasive key.Free()/value.Free() dance
//     grocksdb required is gone. Note that this is not a licence to retain
//     them: they are borrowed, not given. A value from DB.Get is valid only
//     until its Closer is closed and an iterator's key or value only until
//     the next positioning call, because Pebble reuses the buffers. See the
//     "Pebble value lifetimes" note above the state struct in state.go for
//     what the read and rebalance paths rely on.
//
//   - Pure-Go storage, once Phase 2 lands: no librocksdb link, no RocksDB
//     version pin, no C++ toolchain in the storage path. This does not make
//     the replica a cgo-free binary: highctidh, falcon, sphincsplus and
//     sqisign all require cgo, so cmd/replica cannot build with
//     CGO_ENABLED=0 whatever the database is written in.
//
// Phase 2 — remove RocksDB. Phase 1 (this file, plus the Pebble conversion of
// state.go, state_gc.go, and state_rebalance_marker.go) is implemented and
// covered by tests; grocksdb remains only as the migration source. In a future
// release:
//
//  1. Delete this file (it is the only code still importing grocksdb).
//  2. Drop github.com/linxGnu/grocksdb from go.mod/go.sum; go mod tidy. The
//     storage build becomes pure Go, so the RocksDB build machinery becomes
//     obsolete: the rocksdb-local / install-replica-deps targets and the
//     -lrocksdb CGO_LDFLAGS in the top-level Makefile, the RocksDB build in
//     docker/Dockerfile.alpine-base and the rocksdb-10.2.1 base-image pin in
//     docker/Makefile, and the RocksDB install steps in replica/README.md.
//  3. Remove the legacy data automatically: in initDB, once the migration
//     marker is confirmed present, delete <DataDir>/replica.db and log the
//     removal. The marker is also written on fresh installs, so every boot
//     path is covered; no operator flag is required. If old data exists and
//     was not migrated yet, refuse to start. (Leave a note that this code
//     should also be removed eventually in some future version.)
//  4. Trim replica/README.md: drop the "RocksDB is still currently required"
//     note and the ldb dump instructions so the debugging section only covers
//     the Pebble databases.
//  5. Rebuild and re-run the replica tests.
//
// The legacy RocksDB database stored data in two column families that Pebble
// cannot read; the constants below name them and the marker they are migrated
// under.
const (
	// defaultCFName is RocksDB's implicit column family. Box records live here.
	defaultCFName = "default"

	// metadataCFName holds small replica-local bookkeeping records that
	// are not box data, e.g. the storage-replica-set fingerprint used to
	// decide whether a startup rebalance is necessary.
	metadataCFName = "metadata"
)

// migrationDoneKey names the metadata-DB entry that records whether the
// legacy RocksDB database has been migrated into the Pebble databases.
// Its sole purpose is to make the startup migration idempotent.
var migrationDoneKey = []byte("pebble_migration_done")

// migrateBatchSize is how many records accumulate in a Pebble batch
// before it is applied to the database, keeping the migration from
// paying one sync'd write per record.
const migrateBatchSize = 100000

// migrateLegacyRocksDB migrates the legacy RocksDB database (its two
// column families) into the Pebble databases exactly once. It returns
// (true, nil) if a migration was performed. A fresh install with no
// legacy database is recorded as migrated so the check is not repeated
// on subsequent boots.
//
// migrateLegacyRocksDB must only be called after s.db and s.metaDB are
// open. It is invoked from initDB, before any worker goroutines start,
// so there is no concurrent access to the Pebble databases.
func (s *state) migrateLegacyRocksDB() (migrated bool, err error) {
	done, err := s.legacyMigrationDone()
	if err != nil {
		return false, err
	}
	if done {
		return false, nil
	}

	// Fresh install: no legacy database to migrate, but record the
	// marker so we do not probe for RocksDB on every boot.
	if _, err := os.Stat(s.dbPath()); errors.Is(err, os.ErrNotExist) {
		s.log.Debug("state: no legacy RocksDB database present, marking migration complete")
		if err := s.recordMigrationDone(); err != nil {
			return false, err
		}
		return false, nil
	} else if err != nil {
		return false, err
	}

	// The copy runs while the legacy database is still on disk, so the
	// data directory needs room for a second copy of it. Fail here
	// rather than partway through the copy on a full disk.
	if err := s.checkMigrationFreeSpace(); err != nil {
		return false, err
	}

	// Open the legacy database read-only. errorIfWalFileExists is false
	// so an uncleanly closed RocksDB database still migrates.
	opts := grocksdb.NewDefaultOptions()
	defer opts.Destroy()
	cfOpts := []*grocksdb.Options{opts, opts}
	rocksDB, cfHandles, err := grocksdb.OpenDbForReadOnlyColumnFamilies(
		opts, s.dbPath(), []string{defaultCFName, metadataCFName}, cfOpts, false)
	if err != nil {
		return false, fmt.Errorf("state: cannot open legacy RocksDB database for migration: %w", err)
	}
	defer func() {
		for _, h := range cfHandles {
			h.Destroy()
		}
		rocksDB.Close()
	}()

	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	// Count the source records up front so the start and completion logs
	// can carry record counts.
	boxesCount, err := s.countColumnFamily(rocksDB, ro, cfHandles[0])
	if err != nil {
		return false, err
	}
	metaCount, err := s.countColumnFamily(rocksDB, ro, cfHandles[1])
	if err != nil {
		return false, err
	}
	s.log.Noticef("state: migration starting: %s -> %s (%d box records) and %s (%d metadata records)",
		s.dbPath(), s.boxesDBPath(), boxesCount, s.metadataDBPath(), metaCount)

	if err := s.copyColumnFamily(rocksDB, ro, cfHandles[0], s.db); err != nil {
		return false, err
	}
	if err := s.copyColumnFamily(rocksDB, ro, cfHandles[1], s.metaDB); err != nil {
		return false, err
	}

	// Full verification: re-read every record from the Pebble databases
	// and compare it byte-for-byte against the RocksDB source, counting
	// records as we go. The byte check confirms nothing is altered; the
	// returned count, compared against the source count below, confirms
	// nothing is missing or extra.
	boxesStored, err := s.verifyColumnFamily(rocksDB, ro, cfHandles[0], s.db)
	if err != nil {
		return false, err
	}
	metaStored, err := s.verifyColumnFamily(rocksDB, ro, cfHandles[1], s.metaDB)
	if err != nil {
		return false, err
	}
	if boxesStored != boxesCount {
		return false, fmt.Errorf("state: migration verification: box record count mismatch: source %d, stored %d", boxesCount, boxesStored)
	}
	if metaStored != metaCount {
		return false, fmt.Errorf("state: migration verification: metadata record count mismatch: source %d, stored %d", metaCount, metaStored)
	}

	s.log.Noticef("state: migration complete: %d box records and %d metadata records written to Pebble", boxesStored, metaStored)

	if err := s.recordMigrationDone(); err != nil {
		return false, err
	}

	// From here on the legacy database is frozen: nothing writes to it
	// again. Operators need to know that rolling back is not free.
	s.log.Warningf("state: %s is now stale and is retained only as a rollback source. "+
		"Reverting to a RocksDB build will serve pre-migration data, and re-upgrading afterwards will not "+
		"recover anything written in the meantime, because the migration marker is already recorded.",
		s.dbPath())
	return true, nil
}

// checkMigrationFreeSpace reports whether the filesystem backing the
// data directory has room for a second copy of the legacy database.
// The source size is a lower bound on what the copy needs: the Pebble
// databases use comparable compression but also write a WAL. A probe
// failure is not fatal, since refusing to start on an unreadable statfs
// would be worse than attempting the migration.
func (s *state) checkMigrationFreeSpace() error {
	needed, err := dirSizeBytes(s.dbPath())
	if err != nil {
		return fmt.Errorf("state: cannot size legacy database %s: %w", s.dbPath(), err)
	}
	avail, ok := availableBytes(s.server.cfg.DataDir)
	if !ok {
		s.log.Warningf("state: cannot determine free space for %s, attempting migration anyway", s.server.cfg.DataDir)
		return nil
	}
	if avail < needed {
		return fmt.Errorf("state: insufficient free space to migrate: copying %s needs at least %d bytes, %s has %d available",
			s.dbPath(), needed, s.server.cfg.DataDir, avail)
	}
	s.log.Debugf("state: migration free-space check passed: need at least %d bytes, %d available", needed, avail)
	return nil
}

// dirSizeBytes returns the combined size of the regular files under path.
func dirSizeBytes(path string) (uint64, error) {
	var total uint64
	err := filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += uint64(info.Size())
		}
		return nil
	})
	return total, err
}

// legacyMigrationDone reports whether the legacy RocksDB database has
// already been migrated (or was never present).
func (s *state) legacyMigrationDone() (bool, error) {
	_, closer, err := s.metaDB.Get(migrationDoneKey)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	closer.Close()
	return true, nil
}

// recordMigrationDone persists the migration marker.
func (s *state) recordMigrationDone() error {
	return s.metaDB.Set(migrationDoneKey, []byte("done"), nil)
}

// countColumnFamily returns the number of records in a RocksDB column
// family.
func (s *state) countColumnFamily(rocksDB *grocksdb.DB, ro *grocksdb.ReadOptions, cf *grocksdb.ColumnFamilyHandle) (int64, error) {
	it := rocksDB.NewIteratorCF(ro, cf)
	defer it.Close()
	var count int64
	for it.SeekToFirst(); it.Valid(); it.Next() {
		count++
	}
	if err := it.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

// copyColumnFamily copies every record of a RocksDB column family into
// a Pebble database, committing in batches.
func (s *state) copyColumnFamily(rocksDB *grocksdb.DB, ro *grocksdb.ReadOptions, cf *grocksdb.ColumnFamilyHandle, target *pebble.DB) error {
	it := rocksDB.NewIteratorCF(ro, cf)
	defer it.Close()
	batch := target.NewBatch()
	defer batch.Close()
	for it.SeekToFirst(); it.Valid(); it.Next() {
		key := it.Key()
		keyCopy := make([]byte, key.Size())
		copy(keyCopy, key.Data())
		key.Free()
		value := it.Value()
		valueCopy := make([]byte, value.Size())
		copy(valueCopy, value.Data())
		value.Free()
		if err := batch.Set(keyCopy, valueCopy, nil); err != nil {
			return err
		}
		if batch.Count() >= migrateBatchSize {
			if err := target.Apply(batch, nil); err != nil {
				return err
			}
			batch.Reset()
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	if batch.Count() > 0 {
		if err := target.Apply(batch, nil); err != nil {
			return err
		}
	}
	return nil
}

// verifyColumnFamily re-reads every record stored in a Pebble database
// against its RocksDB column family source, comparing the values
// byte-for-byte, and returns the number of records verified. The byte
// check confirms nothing is altered; the returned count, compared by the
// caller against the source count, confirms nothing is missing or extra.
// It returns an error on the first value mismatch. A key absent from the
// source does not surface as an error from GetCF, which reports a missing
// key as an empty value with a nil error; it is caught by the value
// comparison, since no stored record is empty, and by the caller's count
// check.
func (s *state) verifyColumnFamily(rocksDB *grocksdb.DB, ro *grocksdb.ReadOptions, cf *grocksdb.ColumnFamilyHandle, target *pebble.DB) (int64, error) {
	it, err := target.NewIter(&pebble.IterOptions{})
	if err != nil {
		return 0, err
	}
	defer it.Close()
	var count int64
	for it.First(); it.Valid(); it.Next() {
		count++
		key := make([]byte, len(it.Key()))
		copy(key, it.Key())
		want := make([]byte, len(it.Value()))
		copy(want, it.Value())

		got, err := rocksDB.GetCF(ro, cf, key)
		if err != nil {
			return 0, fmt.Errorf("state: migration verification: key %x missing in source: %w", key, err)
		}
		gotData := make([]byte, got.Size())
		copy(gotData, got.Data())
		got.Free()
		if !bytes.Equal(want, gotData) {
			return 0, fmt.Errorf("state: migration verification: value mismatch for key %x", key)
		}
	}
	if err := it.Error(); err != nil {
		return 0, err
	}
	return count, nil
}
