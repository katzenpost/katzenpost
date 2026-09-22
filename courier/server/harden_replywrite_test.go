// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

// TestSpawnReplyWriteBoundsConcurrentWrites pins F3: OnCommand hands each
// client reply to spawnReplyWrite, which must cap the number of
// goroutines parked on a stalled socket write channel instead of
// spawning one per request without bound. With the semaphore slot
// acquired before the goroutine is spawned, a saturated bound makes the
// next spawn a counted drop, not another goroutine.
func TestSpawnReplyWriteBoundsConcurrentWrites(t *testing.T) {
	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	e := &Courier{
		log:           backendLog.GetLogger("test"),
		replyWriteSem: make(chan struct{}, 2),
	}

	// A stalled socket: every write parks until block is closed.
	block := make(chan struct{})
	var writes int32
	e.write = func(cborplugin.Command) {
		atomic.AddInt32(&writes, 1)
		<-block
	}

	// Fill the bound. Both slots are taken synchronously, so both
	// spawns succeed and both goroutines park in e.write.
	require.True(t, e.spawnReplyWrite(&cborplugin.Response{ID: 1}))
	require.True(t, e.spawnReplyWrite(&cborplugin.Response{ID: 2}))

	// The bound is saturated: the next reply is dropped, not spawned,
	// and no third goroutine comes into existence.
	require.False(t, e.spawnReplyWrite(&cborplugin.Response{ID: 3}))

	// Confirm exactly the two admitted writes are running (the dropped
	// one never called e.write).
	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&writes) == 2
	}, time.Second, time.Millisecond, "both admitted writes should be parked in e.write")

	// Draining the stall frees both slots; a later reply is admitted
	// again, proving the bound recovers rather than leaking slots.
	close(block)
	require.Eventually(t, func() bool {
		return e.spawnReplyWrite(&cborplugin.Response{ID: 4})
	}, time.Second, time.Millisecond, "a freed slot must admit a new reply write")
}
