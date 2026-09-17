// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

// TestPruneDocumentsPreserveForPastEpochs proves pruneDocuments honors the
// configured PreserveForPastEpochs retention window rather than a fixed
// constant. With a window of 1 the cutoff is now-1, so documents at now-2 and
// older are pruned; under the previous fixed value of 3 they would be kept.
func TestPruneDocumentsPreserveForPastEpochs(t *testing.T) {
	backend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	db, err := bolt.Open(filepath.Join(t.TempDir(), "persistence.db"), 0600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	now, _, _ := epochtime.Now()

	srv := &Server{
		cfg: &config.Config{Server: &config.Server{PreserveForPastEpochs: 1}},
	}
	st := &state{
		s:   srv,
		log: backend.GetLogger("prune"),
		db:  db,
		documents: map[uint64]*pki.Document{
			now - 4: {},
			now - 3: {},
			now - 2: {},
			now - 1: {},
			now:     {},
		},
	}

	st.Lock()
	st.pruneDocuments()
	st.Unlock()

	kept := func(e uint64) bool { _, ok := st.documents[e]; return ok }

	require.False(t, kept(now-4), "epoch now-4 must be pruned with PreserveForPastEpochs=1")
	require.False(t, kept(now-3), "epoch now-3 must be pruned with PreserveForPastEpochs=1")
	require.False(t, kept(now-2), "epoch now-2 must be pruned with PreserveForPastEpochs=1 (fixed default 3 would keep it)")
	require.True(t, kept(now-1), "epoch now-1 must be retained with PreserveForPastEpochs=1")
	require.True(t, kept(now), "the current epoch must be retained")

	// A window larger than the current epoch must not underflow the cutoff and
	// wipe everything; the current epoch survives.
	big := &state{
		s:         &Server{cfg: &config.Config{Server: &config.Server{PreserveForPastEpochs: now + 100}}},
		log:       backend.GetLogger("prune-big"),
		db:        db,
		documents: map[uint64]*pki.Document{now - 1: {}, now: {}},
	}
	big.Lock()
	big.pruneDocuments()
	big.Unlock()
	_, ok := big.documents[now]
	require.True(t, ok, "an oversized PreserveForPastEpochs must not underflow and prune the current epoch")
}
