// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
)

// TestShutdownCompletesWithFullConnSem verifies shutdown does not depend on the
// connection semaphore having free space. listenWorker's connSem acquire is a
// plain blocking send (a watch on haltedCh there would be dead code, since
// haltedCh is closed only after the WaitGroup drain that waits for the worker);
// shutdown makes progress by closing the listener and accepted connections, not
// by that send observing a halt. A fully occupied semaphore must not stall it.
func TestShutdownCompletesWithFullConnSem(t *testing.T) {
	require := require.New(t)

	lb, err := log.New("", "DEBUG", false)
	require.NoError(err)

	db, err := bolt.Open(filepath.Join(t.TempDir(), "state.db"), 0600, nil)
	require.NoError(err)
	t.Cleanup(func() { _ = db.Close() })

	connSem := make(chan struct{}, 4)
	for i := 0; i < cap(connSem); i++ {
		connSem <- struct{}{}
	}

	srv := &Server{
		cfg:        &config.Config{Server: &config.Server{}},
		log:        lb.GetLogger("srv"),
		logBackend: lb,
		haltedCh:   make(chan interface{}),
		connSem:    connSem,
	}
	srv.state = &state{log: lb.GetLogger("state"), s: srv, db: db}

	done := make(chan struct{})
	go func() {
		srv.Shutdown()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown stalled with a full connection semaphore")
	}
}
