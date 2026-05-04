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

// TestDispatchCopyEnvelopeOneSuccessCountsAsSuccess pins the defensive
// "any Success short-circuits" semantic. With the replica's idempotent
// matching-data path in place this 1-Success/1-BoxAlreadyExists shape
// is no longer expected from the wire — both intermediates should
// agree — but the dispatch logic must still treat any single Success
// as overall success.
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

// TestDispatchCopyEnvelopeSingleBoxAlreadyExistsAborts pins that a
// single non-Success reply is treated as terminal, with no waiting for
// the second intermediate. The replica's idempotent matching-data path
// guarantees that a retried write of byte-identical data returns
// Success — so a BoxAlreadyExists reply unambiguously indicates a
// genuine destination conflict. Retrying would not change the verdict.
func TestDispatchCopyEnvelopeSingleBoxAlreadyExistsAborts(t *testing.T) {
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

	// Wait for both SendMessage calls, then feed ONLY ONE reply —
	// BoxAlreadyExists from one intermediate. The other intermediate's
	// reply is "still in flight" past the deadline.
	for i := 0; i < 2; i++ {
		select {
		case <-conn.sendCalledCh:
		case <-time.After(3 * time.Second):
			t.Fatalf("SendMessage call %d not observed in time", i+1)
		}
	}
	courier.HandleReply(&commands.ReplicaMessageReply{
		EnvelopeHash: envHash,
		ReplicaID:    1,
		ErrorCode:    pigeonhole.ReplicaErrorBoxAlreadyExists,
	})

	select {
	case r := <-resultCh:
		require.False(t, r.ok, "single BoxAlreadyExists must abort the dispatch")
		require.Equal(t, pigeonhole.ReplicaErrorBoxAlreadyExists, r.code)
	case <-time.After(copyWriteReplyTimeout + 5*time.Second):
		t.Fatal("dispatchCopyEnvelope did not return in time — courier waited for second reply instead of aborting")
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
