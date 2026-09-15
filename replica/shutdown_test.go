// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The PKI worker publishes descriptors, which generates envelope keys
// as PEM files in DataDir. A worker left running past Shutdown writes
// into a DataDir the caller believes it is free to delete, which is
// how it surfaced: t.TempDir cleanup failing with "directory not
// empty" after the test's server had reported a complete shutdown.
func TestShutdownHaltsPKIWorker(t *testing.T) {
	setup := createTestSetup(t)
	setup.server.Shutdown()

	require.NotNil(t, setup.server.PKIWorker)
	select {
	case <-setup.server.PKIWorker.HaltCh():
	default:
		t.Fatal("Shutdown returned with the PKI worker still running")
	}
}

// ReplicaMessage commands are handled on goroutines that outlive the
// connection worker which spawned them and that read and write the
// database. If Shutdown returns while one is still running, it races
// state.Close, which nils out the Pebble handles, and the handler
// dereferences nil.
func TestShutdownDrainsInFlightHandlers(t *testing.T) {
	setup := createTestSetup(t)

	var finished atomic.Bool
	setup.server.handlerWg.Add(1)
	go func() {
		defer setup.server.handlerWg.Done()
		time.Sleep(250 * time.Millisecond)
		finished.Store(true)
	}()

	setup.server.Shutdown()
	require.True(t, finished.Load(), "Shutdown returned with a handler still in flight")
}
