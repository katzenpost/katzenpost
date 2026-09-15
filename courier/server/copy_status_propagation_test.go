// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

// waitForCopyComplete spins on the dedup cache until the entry for
// copyKey has InProgress == false. Returns once complete or fails the
// test if the worker doesn't finish inside the deadline.
func waitForCopyComplete(t *testing.T, courier *Courier, copyKey [hash.HashSize]byte) {
	t.Helper()
	require.Eventually(t, func() bool {
		courier.copyDedupCacheLock.RLock()
		defer courier.copyDedupCacheLock.RUnlock()
		st, ok := courier.copyDedupCache[copyKey]
		return ok && !st.InProgress
	}, 2*time.Second, 10*time.Millisecond, "copy worker did not complete")
}

// TestHandleCopyCommandFailedPropagatesReplicaErrorCode is the
// courier-side unit equivalent of TestCopyOntoAlreadyExistingBoxError:
// when processCopyCommand returns a Failed reply carrying a specific
// replica ErrorCode (e.g. BoxAlreadyExists), a subsequent poll with
// the same WriteCap MUST surface that exact code so the client daemon
// can relay it to the thin client.
func TestHandleCopyCommandFailedPropagatesReplicaErrorCode(t *testing.T) {
	courier := createTestCourier(t)

	terminal := &pigeonhole.CourierQueryReply{
		ReplyType: 1,
		CopyCommandReply: &pigeonhole.CopyCommandReply{
			Status:              pigeonhole.CopyStatusFailed,
			ErrorCode:           pigeonhole.ReplicaErrorBoxAlreadyExists,
			FailedEnvelopeIndex: 3,
		},
	}
	release := make(chan struct{})
	close(release)
	courier.processCopyCommandFn = stubProcessCopy(release, terminal)

	cmd := buildCopyCommand([]byte("wc-fail-box-already-exists"))
	_ = courier.handleCopyCommand(cmd)

	waitForCopyComplete(t, courier, hash.Sum256(cmd.WriteCap))

	reply := courier.handleCopyCommand(cmd)
	require.Equal(t, pigeonhole.CopyStatusFailed, reply.CopyCommandReply.Status)
	require.Equal(t, pigeonhole.ReplicaErrorBoxAlreadyExists, reply.CopyCommandReply.ErrorCode,
		"replica ErrorCode must reach the client via the polling status")
	require.Equal(t, uint64(3), reply.CopyCommandReply.FailedEnvelopeIndex,
		"FailedEnvelopeIndex must survive the status cache round-trip")
}

// TestHandleCopyCommandFailedPropagatesLargeEnvelopeIndex pins the
// full u64 range for FailedEnvelopeIndex — clients may copy streams
// larger than u32 and the failure report must not silently truncate.
func TestHandleCopyCommandFailedPropagatesLargeEnvelopeIndex(t *testing.T) {
	courier := createTestCourier(t)

	bigIndex := uint64(0x0102030405060708)
	release := make(chan struct{})
	close(release)
	courier.processCopyCommandFn = stubProcessCopy(release, &pigeonhole.CourierQueryReply{
		ReplyType: 1,
		CopyCommandReply: &pigeonhole.CopyCommandReply{
			Status:              pigeonhole.CopyStatusFailed,
			ErrorCode:           pigeonhole.ReplicaErrorInvalidSignature,
			FailedEnvelopeIndex: bigIndex,
		},
	})

	cmd := buildCopyCommand([]byte("wc-fail-big-index"))
	_ = courier.handleCopyCommand(cmd)

	waitForCopyComplete(t, courier, hash.Sum256(cmd.WriteCap))

	reply := courier.handleCopyCommand(cmd)
	require.Equal(t, pigeonhole.CopyStatusFailed, reply.CopyCommandReply.Status)
	require.Equal(t, pigeonhole.ReplicaErrorInvalidSignature, reply.CopyCommandReply.ErrorCode)
	require.Equal(t, bigIndex, reply.CopyCommandReply.FailedEnvelopeIndex)
}

// TestHandleCopyCommandConcurrentPollsAllSeeInProgress models an
// aggressively-retrying daemon hammering handleCopyCommand while the
// worker is still running. Every concurrent poll must observe
// InProgress — not a stale nil Result, not a panic, not a terminal
// status before the worker has actually finished.
func TestHandleCopyCommandConcurrentPollsAllSeeInProgress(t *testing.T) {
	courier := createTestCourier(t)

	release := make(chan struct{})
	defer close(release)
	courier.processCopyCommandFn = stubProcessCopy(release, &pigeonhole.CourierQueryReply{
		ReplyType: 1,
		CopyCommandReply: &pigeonhole.CopyCommandReply{
			Status: pigeonhole.CopyStatusSucceeded,
		},
	})

	cmd := buildCopyCommand([]byte("wc-concurrent-polls"))
	// Prime the cache so the first call kicks off the worker.
	firstReply := courier.handleCopyCommand(cmd)
	require.Equal(t, pigeonhole.CopyStatusInProgress, firstReply.CopyCommandReply.Status)

	const pollers = 32
	var wg sync.WaitGroup
	var wrongStatus atomic.Int32
	var nilReply atomic.Int32
	start := make(chan struct{})
	for i := 0; i < pollers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			reply := courier.handleCopyCommand(cmd)
			if reply == nil || reply.CopyCommandReply == nil {
				nilReply.Add(1)
				return
			}
			if reply.CopyCommandReply.Status != pigeonhole.CopyStatusInProgress {
				wrongStatus.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	require.Zero(t, nilReply.Load(), "no poller should receive a nil reply")
	require.Zero(t, wrongStatus.Load(), "every concurrent poll must see InProgress")
}

// TestHandleCopyCommandWorkerPanicReturnsFailed pins the recover path
// in runCopyCommand — a panic inside processCopyCommandFn must NOT
// leave the entry stuck InProgress forever; subsequent polls must
// receive a terminal Failed reply so the client's polling loop can
// finish instead of hammering the courier indefinitely.
func TestHandleCopyCommandWorkerPanicReturnsFailed(t *testing.T) {
	courier := createTestCourier(t)

	courier.processCopyCommandFn = func(*pigeonhole.CopyCommand) *pigeonhole.CourierQueryReply {
		panic("simulated Copy worker panic")
	}

	cmd := buildCopyCommand([]byte("wc-worker-panic"))
	first := courier.handleCopyCommand(cmd)
	require.Equal(t, pigeonhole.CopyStatusInProgress, first.CopyCommandReply.Status,
		"first call should still return InProgress even though the worker is about to panic")

	waitForCopyComplete(t, courier, hash.Sum256(cmd.WriteCap))

	reply := courier.handleCopyCommand(cmd)
	require.Equal(t, pigeonhole.CopyStatusFailed, reply.CopyCommandReply.Status,
		"panicked worker must produce a terminal Failed status, not a stuck InProgress")
}

// TestHandleCopyCommandIndependentWriteCaps ensures two in-flight Copy
// commands on different WriteCaps don't share state — status cache
// dedup is per-WriteCap-hash, not global.
func TestHandleCopyCommandIndependentWriteCaps(t *testing.T) {
	courier := createTestCourier(t)

	// Worker A: blocks on releaseA, returns Succeeded.
	// Worker B: blocks on releaseB, returns Failed with StorageFull.
	releaseA := make(chan struct{})
	releaseB := make(chan struct{})

	courier.processCopyCommandFn = func(cmd *pigeonhole.CopyCommand) *pigeonhole.CourierQueryReply {
		// Dispatch to the right channel based on WriteCap bytes so
		// the two workers don't interfere.
		if string(cmd.WriteCap) == "wc-independent-A" {
			<-releaseA
			return &pigeonhole.CourierQueryReply{
				ReplyType: 1,
				CopyCommandReply: &pigeonhole.CopyCommandReply{
					Status: pigeonhole.CopyStatusSucceeded,
				},
			}
		}
		<-releaseB
		return &pigeonhole.CourierQueryReply{
			ReplyType: 1,
			CopyCommandReply: &pigeonhole.CopyCommandReply{
				Status:    pigeonhole.CopyStatusFailed,
				ErrorCode: pigeonhole.ReplicaErrorStorageFull,
			},
		}
	}

	cmdA := buildCopyCommand([]byte("wc-independent-A"))
	cmdB := buildCopyCommand([]byte("wc-independent-B"))

	_ = courier.handleCopyCommand(cmdA)
	_ = courier.handleCopyCommand(cmdB)

	// Unblock A, leave B running.
	close(releaseA)
	waitForCopyComplete(t, courier, hash.Sum256(cmdA.WriteCap))

	aReply := courier.handleCopyCommand(cmdA)
	require.Equal(t, pigeonhole.CopyStatusSucceeded, aReply.CopyCommandReply.Status)

	bReply := courier.handleCopyCommand(cmdB)
	require.Equal(t, pigeonhole.CopyStatusInProgress, bReply.CopyCommandReply.Status,
		"B must still be InProgress — A's completion must not leak into B's state")

	// Finish B.
	close(releaseB)
	waitForCopyComplete(t, courier, hash.Sum256(cmdB.WriteCap))

	bFinal := courier.handleCopyCommand(cmdB)
	require.Equal(t, pigeonhole.CopyStatusFailed, bFinal.CopyCommandReply.Status)
	require.Equal(t, pigeonhole.ReplicaErrorStorageFull, bFinal.CopyCommandReply.ErrorCode)
}
