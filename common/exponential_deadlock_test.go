// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"
	"time"
)

// TestExpDistOpsNotStarvedByBlockedTick reproduces the courier
// outgoing-connection wedge: with no OutCh consumer the worker parks
// delivering a tick, and control ops must still be serviced. The op
// sequence below is exactly what a connection teardown followed by a
// reconnect performs; before the fix the UpdateRate call blocked
// forever (opCh full, worker parked on outCh) and this test timed out.
func TestExpDistOpsNotStarvedByBlockedTick(t *testing.T) {
	t.Parallel()
	e := NewExpDist()
	defer e.Halt()

	// Fast rate, connected, and nobody reading OutCh: the worker
	// buffers one tick and parks delivering the next.
	e.UpdateRate(1)
	e.UpdateConnectionStatus(true)
	time.Sleep(200 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		e.UpdateConnectionStatus(false)
		e.UpdateRate(200)
		e.UpdateConnectionStatus(true)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ExpDist control ops deadlocked behind an undeliverable tick")
	}
}
