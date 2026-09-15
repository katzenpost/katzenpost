// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

// buildCopyCommand returns a CopyCommand with the provided WriteCap
// bytes. The contents aren't parsed by handleCopyCommand — only the
// WriteCap hash (the dedup/status-cache key) matters for these tests.
func buildCopyCommand(writeCap []byte) *pigeonhole.CopyCommand {
	return &pigeonhole.CopyCommand{
		WriteCapLen: uint32(len(writeCap)),
		WriteCap:    writeCap,
	}
}

// stubProcessCopy returns a processCopyCommandFn that blocks until
// release is closed, then returns the given reply. Tests use this to
// park a Copy in the "in progress" state while polling.
func stubProcessCopy(release <-chan struct{}, reply *pigeonhole.CourierQueryReply) func(*pigeonhole.CopyCommand) *pigeonhole.CourierQueryReply {
	return func(*pigeonhole.CopyCommand) *pigeonhole.CourierQueryReply {
		<-release
		return reply
	}
}

// TestHandleCopyCommandFirstCallImmediateInProgress asserts that the
// first handleCopyCommand for a fresh WriteCap returns immediately
// with Status=InProgress, rather than blocking on processing.
func TestHandleCopyCommandFirstCallImmediateInProgress(t *testing.T) {
	courier := createTestCourier(t)
	release := make(chan struct{})
	defer close(release)

	terminal := &pigeonhole.CourierQueryReply{
		ReplyType: 1,
		CopyCommandReply: &pigeonhole.CopyCommandReply{
			Status: pigeonhole.CopyStatusSucceeded,
		},
	}
	courier.processCopyCommandFn = stubProcessCopy(release, terminal)

	cmd := buildCopyCommand([]byte("writecap-async-initial"))

	start := time.Now()
	reply := courier.handleCopyCommand(cmd)
	elapsed := time.Since(start)

	require.NotNil(t, reply)
	require.NotNil(t, reply.CopyCommandReply)
	require.Equal(t, pigeonhole.CopyStatusInProgress, reply.CopyCommandReply.Status,
		"first call must return InProgress immediately")
	require.Less(t, elapsed, 200*time.Millisecond,
		"handleCopyCommand must not block on processing (elapsed=%v)", elapsed)
}

// TestHandleCopyCommandPollReturnsInProgress asserts that polling the
// same WriteCap while the background goroutine is still running also
// returns InProgress (not a blocked wait).
func TestHandleCopyCommandPollReturnsInProgress(t *testing.T) {
	courier := createTestCourier(t)
	release := make(chan struct{})
	defer close(release)

	courier.processCopyCommandFn = stubProcessCopy(release, &pigeonhole.CourierQueryReply{
		ReplyType: 1,
		CopyCommandReply: &pigeonhole.CopyCommandReply{
			Status: pigeonhole.CopyStatusSucceeded,
		},
	})

	cmd := buildCopyCommand([]byte("writecap-poll-inprogress"))
	_ = courier.handleCopyCommand(cmd) // kicks off goroutine

	// Poll — still in progress because release hasn't fired.
	start := time.Now()
	reply := courier.handleCopyCommand(cmd)
	elapsed := time.Since(start)

	require.Equal(t, pigeonhole.CopyStatusInProgress, reply.CopyCommandReply.Status)
	require.Less(t, elapsed, 200*time.Millisecond,
		"poll must not block waiting for completion (elapsed=%v)", elapsed)
}

// TestHandleCopyCommandPollReturnsTerminalStatus asserts that once the
// background goroutine completes, a subsequent poll with the same
// WriteCap returns the cached terminal reply.
func TestHandleCopyCommandPollReturnsTerminalStatus(t *testing.T) {
	courier := createTestCourier(t)
	release := make(chan struct{})

	terminal := &pigeonhole.CourierQueryReply{
		ReplyType: 1,
		CopyCommandReply: &pigeonhole.CopyCommandReply{
			Status:              pigeonhole.CopyStatusFailed,
			ErrorCode:           pigeonhole.ReplicaErrorStorageFull,
			FailedEnvelopeIndex: 7,
		},
	}
	courier.processCopyCommandFn = stubProcessCopy(release, terminal)

	cmd := buildCopyCommand([]byte("writecap-poll-terminal"))
	_ = courier.handleCopyCommand(cmd) // kicks off goroutine

	// Let the background goroutine complete.
	close(release)

	// Wait for the completion signal so the test is deterministic.
	copyKey := hash.Sum256(cmd.WriteCap)
	require.Eventually(t, func() bool {
		courier.copyDedupCacheLock.RLock()
		defer courier.copyDedupCacheLock.RUnlock()
		state, ok := courier.copyDedupCache[copyKey]
		return ok && !state.InProgress
	}, 2*time.Second, 10*time.Millisecond, "background goroutine should complete")

	reply := courier.handleCopyCommand(cmd)

	require.Equal(t, pigeonhole.CopyStatusFailed, reply.CopyCommandReply.Status)
	require.Equal(t, pigeonhole.ReplicaErrorStorageFull, reply.CopyCommandReply.ErrorCode)
	require.Equal(t, uint64(7), reply.CopyCommandReply.FailedEnvelopeIndex)
}

// TestHandleCopyCommandExpiredTTLReprocesses asserts that a completed
// Copy whose cache entry has aged past CopyDedupCacheTTL gets
// reprocessed on the next poll rather than returning stale state.
func TestHandleCopyCommandExpiredTTLReprocesses(t *testing.T) {
	courier := createTestCourier(t)

	var calls int
	release := make(chan struct{})
	close(release)
	courier.processCopyCommandFn = func(*pigeonhole.CopyCommand) *pigeonhole.CourierQueryReply {
		calls++
		return &pigeonhole.CourierQueryReply{
			ReplyType: 1,
			CopyCommandReply: &pigeonhole.CopyCommandReply{
				Status: pigeonhole.CopyStatusSucceeded,
			},
		}
	}

	cmd := buildCopyCommand([]byte("writecap-ttl-expiry"))
	_ = courier.handleCopyCommand(cmd)

	copyKey := hash.Sum256(cmd.WriteCap)
	require.Eventually(t, func() bool {
		courier.copyDedupCacheLock.RLock()
		defer courier.copyDedupCacheLock.RUnlock()
		st, ok := courier.copyDedupCache[copyKey]
		return ok && !st.InProgress
	}, 2*time.Second, 10*time.Millisecond)

	// Age the entry past the TTL.
	courier.copyDedupCacheLock.Lock()
	courier.copyDedupCache[copyKey].CompletedAt = time.Now().Add(-2 * CopyDedupCacheTTL)
	courier.copyDedupCacheLock.Unlock()

	reply := courier.handleCopyCommand(cmd)
	require.Equal(t, pigeonhole.CopyStatusInProgress, reply.CopyCommandReply.Status,
		"TTL-expired entry must be reprocessed")
	require.Eventually(t, func() bool {
		courier.copyDedupCacheLock.RLock()
		defer courier.copyDedupCacheLock.RUnlock()
		st, ok := courier.copyDedupCache[copyKey]
		return ok && !st.InProgress
	}, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, 2, calls, "processCopyCommand must have run twice")
}

// TestCopyDedupCacheTTLIsThirtyMinutes pins the TTL constant so a
// refactor doesn't silently change the grace window clients depend on
// for late polls after reconnection.
func TestCopyDedupCacheTTLIsThirtyMinutes(t *testing.T) {
	require.Equal(t, 30*time.Minute, CopyDedupCacheTTL)
}
