// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/stretchr/testify/require"
)

func TestCleanupLegacyDatabaseRemovesMigratedDatabase(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-legacy-remove-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	// First boot is a fresh install: the marker is recorded, with no
	// legacy database to remove.
	st := newTestState(t, dataDir)
	st.initDB()
	st.Close()

	// Simulate a migrated deployment that still carries the legacy
	// RocksDB database on disk.
	legacy := filepath.Join(dataDir, "replica.db")
	require.NoError(t, os.WriteFile(legacy, []byte("stale rocksdb data"), 0600))

	// Reopening must remove the legacy database once the marker is
	// present. Close explicitly: the two Pebble databases are
	// file-locked by the open state, so a second state cannot be
	// opened over them until this one is closed.
	st2 := newTestState(t, dataDir)
	st2.initDB()
	defer st2.Close()

	_, err = os.Stat(legacy)
	require.ErrorIs(t, err, os.ErrNotExist, "migrated legacy database must be removed on boot")
}

func TestCleanupLegacyDatabaseRefusesUnmigrated(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-legacy-refuse-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	legacy := filepath.Join(dataDir, "replica.db")
	require.NoError(t, os.WriteFile(legacy, []byte("rocksdb data"), 0600))

	st := newTestState(t, dataDir)
	defer st.Close()

	// Open the Pebble databases without running initDB (initDB would
	// panic on the refusal), then drive the cleanup directly.
	st.db, err = pebble.Open(st.boxesDBPath(), &pebble.Options{})
	require.NoError(t, err)
	st.metaDB, err = pebble.Open(st.metadataDBPath(), &pebble.Options{})
	require.NoError(t, err)

	err = st.cleanupLegacyDatabase()
	require.Error(t, err)
	require.ErrorContains(t, err, "has no migration marker")

	// The legacy database must be left untouched for the operator to
	// recover, and no marker may be written.
	_, err = os.Stat(legacy)
	require.NoError(t, err)
	done, err := st.legacyMigrationDone()
	require.NoError(t, err)
	require.False(t, done)
}

func TestCleanupLegacyDatabaseFreshInstallWritesMarker(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-legacy-fresh-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	st := newTestState(t, dataDir)
	st.initDB()
	defer st.Close()

	// No legacy database was present: the marker must be recorded so
	// later boots do not repeat the legacy check.
	done, err := st.legacyMigrationDone()
	require.NoError(t, err)
	require.True(t, done)
}
