// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"errors"
	"fmt"
	"os"

	"github.com/cockroachdb/pebble"
)

// migrationDoneKey names the metadata-DB entry that records whether the
// legacy RocksDB database (<DataDir>/replica.db) has been migrated into
// the Pebble databases. Phase 1 wrote it once the migration (or a fresh
// install) completed; this file reads it to decide whether the legacy
// database may be removed.
var migrationDoneKey = []byte("pebble_migration_done")

// cleanupLegacyDatabase removes the legacy RocksDB database once the
// migration marker is present, and refuses to start if unmigrated legacy
// data is still on disk.
//
// This is the tail end of the Phase 1 Pebble migration: replica storage
// now lives entirely in two Pebble databases, and the marker-gated
// removal below is what lets operators shed the RocksDB files without an
// explicit flag. The marker is also written on fresh installs, so every
// boot path reaches the deletion check.
//
// This whole file can be removed in a future release, once every
// deployment has booted past the RocksDB era; the marker then serves no
// purpose.
func (s *state) cleanupLegacyDatabase() error {
	done, err := s.legacyMigrationDone()
	if err != nil {
		return err
	}

	_, statErr := os.Stat(s.dbPath())
	switch {
	case statErr == nil:
		// Legacy database present.
	case errors.Is(statErr, os.ErrNotExist):
		// No legacy database.
	default:
		return statErr
	}
	legacyPresent := statErr == nil

	if done {
		if legacyPresent {
			s.log.Noticef("state: removing migrated legacy RocksDB database %s", s.dbPath())
			if err := os.RemoveAll(s.dbPath()); err != nil {
				return err
			}
		}
		return nil
	}

	if legacyPresent {
		return fmt.Errorf("state: legacy RocksDB database %s has no migration marker; refusing to start: boot the replica once through a release that migrates RocksDB to Pebble, or remove the legacy database if the data is expendable", s.dbPath())
	}

	// Fresh install: no legacy database to remove, but record the marker
	// so the legacy check is not repeated on subsequent boots.
	s.log.Debug("state: no legacy RocksDB database present, marking migration complete")
	return s.recordMigrationDone()
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
