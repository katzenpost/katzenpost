// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

// fakeConnector is a test-only GenericConnector that records every
// DispatchMessage call and emits on sendCalledCh, so a test can
// synchronize with the moment the courier has dispatched to both
// intermediates before injecting fake replica replies.
type fakeConnector struct {
	mu           sync.Mutex
	sendErr      error
	sendCalledCh chan uint8
	lastSent     map[uint8]*commands.ReplicaMessage
}

func newFakeConnector() *fakeConnector {
	return &fakeConnector{
		sendCalledCh: make(chan uint8, 4),
		lastSent:     make(map[uint8]*commands.ReplicaMessage),
	}
}

func (f *fakeConnector) Halt()                           {}
func (f *fakeConnector) Server() *Server                 { return nil }
func (f *fakeConnector) OnClosedConn(conn *outgoingConn) {}
func (f *fakeConnector) CloseAllCh() chan interface{}    { return make(chan interface{}) }
func (f *fakeConnector) ForceUpdate()                    {}

func (f *fakeConnector) DispatchMessage(dest uint8, msg *commands.ReplicaMessage) error {
	f.mu.Lock()
	if f.sendErr != nil {
		err := f.sendErr
		f.mu.Unlock()
		return err
	}
	f.lastSent[dest] = msg
	f.mu.Unlock()

	select {
	case f.sendCalledCh <- dest:
	default:
	}
	return nil
}

// buildTestCourierEnvelope constructs a minimal CourierEnvelope with
// deterministic SenderPubkey + Ciphertext so its EnvelopeHash is
// stable across the dispatch + reply round-trip inside a test.
func buildTestCourierEnvelope() *pigeonhole.CourierEnvelope {
	senderKey := bytes.Repeat([]byte{0x77}, 16)
	ciphertext := bytes.Repeat([]byte{0x88}, 32)
	return &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{1, 2},
		Dek1:                 [60]uint8{},
		Dek2:                 [60]uint8{},
		ReplyIndex:           0,
		Epoch:                42,
		SenderPubkeyLen:      uint16(len(senderKey)),
		SenderPubkey:         senderKey,
		CiphertextLen:        uint32(len(ciphertext)),
		Ciphertext:           ciphertext,
	}
}

// runDispatchCopyEnvelopeTest drives dispatchCopyEnvelope, waits for
// the intermediates to be contacted, injects the provided replies via
// HandleReply, and returns the (ok, replicaErr) outcome.
func runDispatchCopyEnvelopeTest(t *testing.T, courier *Courier, conn *fakeConnector, envelope *pigeonhole.CourierEnvelope, replies []*commands.ReplicaMessageReply) (bool, uint8) {
	t.Helper()

	type result struct {
		ok   bool
		code uint8
	}
	resultCh := make(chan result, 1)
	go func() {
		ok, code := courier.dispatchCopyEnvelope(envelope)
		resultCh <- result{ok, code}
	}()

	// Wait for both SendMessage calls so replies arrive after
	// the copyCache channel has been registered.
	for i := 0; i < 2; i++ {
		select {
		case <-conn.sendCalledCh:
		case <-time.After(3 * time.Second):
			t.Fatalf("SendMessage call %d not observed in time", i+1)
		}
	}

	for _, r := range replies {
		courier.HandleReply(r)
	}

	select {
	case r := <-resultCh:
		return r.ok, r.code
	case <-time.After(5 * time.Second):
		t.Fatal("dispatchCopyEnvelope did not return in time")
		return false, 0
	}
}

// TestDispatchCopyEnvelopeBothReplicasBoxAlreadyExistsAborts is the
// unit-test replacement for the integration test
// TestCopyOntoAlreadyExistingBoxError. When both intermediate replicas
// reply with BoxAlreadyExists (i.e. the destination box is already
// written), the Copy envelope dispatch must report failure with that
// error code so processCopyCommand can abort and surface the error to
// the client via Status=Failed.
func TestDispatchCopyEnvelopeBothReplicasBoxAlreadyExistsAborts(t *testing.T) {
	courier := createTestCourier(t)
	conn := newFakeConnector()
	courier.server.connector = conn

	envelope := buildTestCourierEnvelope()
	envHash := envelope.EnvelopeHash()

	replies := []*commands.ReplicaMessageReply{
		{EnvelopeHash: envHash, ReplicaID: 1, ErrorCode: pigeonhole.ReplicaErrorBoxAlreadyExists},
		{EnvelopeHash: envHash, ReplicaID: 2, ErrorCode: pigeonhole.ReplicaErrorBoxAlreadyExists},
	}

	ok, code := runDispatchCopyEnvelopeTest(t, courier, conn, envelope, replies)

	require.False(t, ok, "dispatch must fail when both replicas reject")
	require.Equal(t, pigeonhole.ReplicaErrorBoxAlreadyExists, code,
		"courier must surface BoxAlreadyExists to the Copy command")
}

// TestDispatchCopyEnvelopeOneSuccessCountsAsSuccess covers the
// replication-race case: two intermediates may proxy to the same shard
// — the first wins the write and the second sees BoxAlreadyExists.
// The copy envelope has been persisted by at least one path, so
// dispatch should report success and let the Copy continue.
func TestDispatchCopyEnvelopeOneSuccessCountsAsSuccess(t *testing.T) {
	courier := createTestCourier(t)
	conn := newFakeConnector()
	courier.server.connector = conn

	envelope := buildTestCourierEnvelope()
	envHash := envelope.EnvelopeHash()

	replies := []*commands.ReplicaMessageReply{
		{EnvelopeHash: envHash, ReplicaID: 1, ErrorCode: pigeonhole.ReplicaSuccess},
		{EnvelopeHash: envHash, ReplicaID: 2, ErrorCode: pigeonhole.ReplicaErrorBoxAlreadyExists},
	}

	ok, code := runDispatchCopyEnvelopeTest(t, courier, conn, envelope, replies)

	require.True(t, ok, "at least one success must count as overall success")
	require.Equal(t, uint8(0), code)
}

// TestDispatchCopyEnvelopeBoxAlreadyExistsOnRetryIsSuccess pins the
// retry-idempotency invariant: if attempt 0 times out without replies
// and attempt 1 sees BoxAlreadyExists from both intermediates, that
// means attempt 0's writes actually landed at the replicas and only
// the replies were lost. The dispatch must treat this as success, not
// as the "destination pre-existed" failure.
//
// Regression for a flaky integration-test failure in
// TestCreateCourierEnvelopesFromPayload under CI load.
func TestDispatchCopyEnvelopeBoxAlreadyExistsOnRetryIsSuccess(t *testing.T) {
	courier := createTestCourier(t)
	conn := newFakeConnector()
	courier.server.connector = conn

	envelope := buildTestCourierEnvelope()
	envHash := envelope.EnvelopeHash()

	type result struct {
		ok   bool
		code uint8
	}
	resultCh := make(chan result, 1)
	go func() {
		ok, code := courier.dispatchCopyEnvelope(envelope)
		resultCh <- result{ok, code}
	}()

	// Attempt 0: wait for both SendMessage calls, then DON'T feed
	// any replies. dispatchCopyEnvelope will block until
	// copyWriteReplyTimeout elapses (15s) and then retry.
	for i := 0; i < 2; i++ {
		select {
		case <-conn.sendCalledCh:
		case <-time.After(3 * time.Second):
			t.Fatalf("attempt 0: SendMessage call %d not observed in time", i+1)
		}
	}

	// Attempt 1: after the timeout + backoff, the courier re-sends.
	// This time we feed BoxAlreadyExists replies from both
	// intermediates, simulating "our prior attempt's writes actually
	// landed but the replies got lost."
	for i := 0; i < 2; i++ {
		select {
		case <-conn.sendCalledCh:
		case <-time.After(copyWriteReplyTimeout + copyBackoffBase*2 + 3*time.Second):
			t.Fatalf("attempt 1: SendMessage call %d not observed in time", i+1)
		}
	}

	courier.HandleReply(&commands.ReplicaMessageReply{
		EnvelopeHash: envHash,
		ReplicaID:    1,
		ErrorCode:    pigeonhole.ReplicaErrorBoxAlreadyExists,
	})
	courier.HandleReply(&commands.ReplicaMessageReply{
		EnvelopeHash: envHash,
		ReplicaID:    2,
		ErrorCode:    pigeonhole.ReplicaErrorBoxAlreadyExists,
	})

	select {
	case r := <-resultCh:
		require.True(t, r.ok, "BoxAlreadyExists on attempt>0 must count as success (our prior write landed)")
		require.Equal(t, uint8(0), r.code)
	case <-time.After(copyWriteReplyTimeout + 5*time.Second):
		t.Fatal("dispatchCopyEnvelope did not return in time")
	}
}

// TestDispatchCopyEnvelopeSingleBoxAlreadyExistsReplyIsTransient is the
// regression for the CI flake in TestCreateCourierEnvelopesFromPayload.
//
// K=2 normal operation: both intermediates proxy to the same shard for
// a given box. One of them writes first (Success); the other sees the
// peer's write and replies BoxAlreadyExists. When the Success reply is
// delayed past copyWriteReplyTimeout and only the BoxAlreadyExists
// reply lands in time, the courier MUST treat the shortfall as
// transient and retry — not conclude "both intermediates report
// BoxAlreadyExists" from a single reply and abort the Copy.
//
// This test shapes that exact scenario and relies on attempt 1's
// BoxAlreadyExists-from-both behaving as the "our prior write landed"
// success already pinned by TestDispatchCopyEnvelopeBoxAlreadyExistsOnRetryIsSuccess.
func TestDispatchCopyEnvelopeSingleBoxAlreadyExistsReplyIsTransient(t *testing.T) {
	courier := createTestCourier(t)
	conn := newFakeConnector()
	courier.server.connector = conn

	envelope := buildTestCourierEnvelope()
	envHash := envelope.EnvelopeHash()

	type result struct {
		ok   bool
		code uint8
	}
	resultCh := make(chan result, 1)
	go func() {
		ok, code := courier.dispatchCopyEnvelope(envelope)
		resultCh <- result{ok, code}
	}()

	// Attempt 0: wait for both SendMessage calls, then feed ONLY ONE
	// reply — BoxAlreadyExists. The peer's Success reply is "still in
	// flight" past the deadline. Pre-fix, the courier terminated this
	// attempt with CopyStatusFailed; post-fix, it must retry.
	for i := 0; i < 2; i++ {
		select {
		case <-conn.sendCalledCh:
		case <-time.After(3 * time.Second):
			t.Fatalf("attempt 0: SendMessage call %d not observed in time", i+1)
		}
	}
	courier.HandleReply(&commands.ReplicaMessageReply{
		EnvelopeHash: envHash,
		ReplicaID:    1,
		ErrorCode:    pigeonhole.ReplicaErrorBoxAlreadyExists,
	})

	// Attempt 1: after the deadline + backoff, the courier must
	// re-dispatch. Observing both SendMessage calls here is the
	// behavioral proof that "1 reply + BoxAlreadyExists" was treated as
	// transient, not terminal.
	for i := 0; i < 2; i++ {
		select {
		case <-conn.sendCalledCh:
		case <-time.After(copyWriteReplyTimeout + copyBackoffBase*2 + 3*time.Second):
			t.Fatalf("attempt 1: SendMessage call %d not observed in time — courier aborted instead of retrying", i+1)
		}
	}

	// Feed the full K=2 response on attempt 1: both BoxAlreadyExists.
	// attempt>0 treats this as "our prior write landed" → success.
	courier.HandleReply(&commands.ReplicaMessageReply{
		EnvelopeHash: envHash,
		ReplicaID:    1,
		ErrorCode:    pigeonhole.ReplicaErrorBoxAlreadyExists,
	})
	courier.HandleReply(&commands.ReplicaMessageReply{
		EnvelopeHash: envHash,
		ReplicaID:    2,
		ErrorCode:    pigeonhole.ReplicaErrorBoxAlreadyExists,
	})

	select {
	case r := <-resultCh:
		require.True(t, r.ok, "single-reply BoxAlreadyExists must not terminate the dispatch")
		require.Equal(t, uint8(0), r.code)
	case <-time.After(copyWriteReplyTimeout + 5*time.Second):
		t.Fatal("dispatchCopyEnvelope did not return in time")
	}
}

// TestDispatchCopyEnvelopeAllSuccess is the happy path — both
// intermediates write cleanly.
func TestDispatchCopyEnvelopeAllSuccess(t *testing.T) {
	courier := createTestCourier(t)
	conn := newFakeConnector()
	courier.server.connector = conn

	envelope := buildTestCourierEnvelope()
	envHash := envelope.EnvelopeHash()

	replies := []*commands.ReplicaMessageReply{
		{EnvelopeHash: envHash, ReplicaID: 1, ErrorCode: pigeonhole.ReplicaSuccess},
		{EnvelopeHash: envHash, ReplicaID: 2, ErrorCode: pigeonhole.ReplicaSuccess},
	}

	ok, code := runDispatchCopyEnvelopeTest(t, courier, conn, envelope, replies)

	require.True(t, ok)
	require.Equal(t, uint8(0), code)
}
