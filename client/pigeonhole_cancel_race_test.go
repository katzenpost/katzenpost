// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/client/thin"
)

// newCancelRaceDaemon constructs the minimum Daemon shape the three
// tests below need: replyLock, the two ARQ maps, a started timer
// queue, and a stub listener (via setupDaemonWithMockConn). Tests own
// their own arqMessage installations.
func newCancelRaceDaemon(t *testing.T) (*Daemon, *[AppIDLength]byte, chan *Response) {
	t.Helper()
	d, appID, responseCh := setupDaemonWithMockConn(t)
	d.arqTimerQueue = NewTimerQueue(func(_ interface{}) {})
	d.arqTimerQueue.Start()
	t.Cleanup(func() { d.arqTimerQueue.Halt() })
	return d, appID, responseCh
}

// installCopyARQ pre-inserts an ARQMessage into both maps under a known
// SURBID. Mimics the post-`StartResendingCopyCommand` steady state.
func installCopyARQ(d *Daemon, appID *[AppIDLength]byte, surbID *[sphinxConstants.SURBIDLength]byte) (*ARQMessage, *[32]byte) {
	writeCapHash := &[32]byte{}
	copy(writeCapHash[:], []byte("writecap-hash-cancel-race-test00"))

	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("copy-query-00001"))

	arqMessage := &ARQMessage{
		MessageType:  ARQMessageTypeCopyCommand,
		AppID:        appID,
		QueryID:      queryID,
		EnvelopeHash: writeCapHash,
		SURBID:       surbID,
		Payload:      []byte("copy-command-payload"),
	}

	d.replyLock.Lock()
	d.arqSurbIDMap[*surbID] = arqMessage
	d.arqEnvelopeHashMap[*writeCapHash] = surbID
	d.replyLock.Unlock()

	return arqMessage, writeCapHash
}

// TestScheduleCopyCommandPollRotatesNormally pins the happy-path
// rotation: given an ARQ message tracked under oldSurbID in both
// maps, scheduleCopyCommandPoll must delete the old entry, install
// the new placeholder in both maps, and update arqMessage.SURBID to
// the placeholder. This is the post-fix invariant for the ordinary
// InProgress poll.
func TestScheduleCopyCommandPollRotatesNormally(t *testing.T) {
	d, appID, _ := newCancelRaceDaemon(t)

	oldSurbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(oldSurbID[:], []byte("old-rotate-00001"))
	arqMessage, writeCapHash := installCopyARQ(d, appID, oldSurbID)

	d.scheduleCopyCommandPoll(arqMessage)

	d.replyLock.Lock()
	defer d.replyLock.Unlock()

	_, oldStillPresent := d.arqSurbIDMap[*oldSurbID]
	require.False(t, oldStillPresent, "old SURBID entry must be removed on rotation")

	placeholder, ok := d.arqEnvelopeHashMap[*writeCapHash]
	require.True(t, ok, "envelope hash must point at the new placeholder")
	require.NotNil(t, placeholder)
	require.NotEqual(t, *oldSurbID, *placeholder, "placeholder must differ from the old SURBID")

	msg, ok := d.arqSurbIDMap[*placeholder]
	require.True(t, ok, "placeholder must be registered in arqSurbIDMap")
	require.Same(t, arqMessage, msg)

	require.Same(t, placeholder, arqMessage.SURBID, "arqMessage.SURBID must be updated to placeholder")
}

// TestScheduleCopyCommandPollAbortsIfCancelled pins the race-fix
// invariant: if a cancel has already removed the arqMessage from the
// maps before scheduleCopyCommandPoll runs, the schedule must detect
// the absence and make no map writes, leaving the cancellation
// intact. Pre-fix, scheduleCopyCommandPoll unconditionally re-added
// entries, silently un-doing the cancel.
func TestScheduleCopyCommandPollAbortsIfCancelled(t *testing.T) {
	d, appID, responseCh := newCancelRaceDaemon(t)

	oldSurbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(oldSurbID[:], []byte("old-abort-000001"))
	arqMessage, writeCapHash := installCopyARQ(d, appID, oldSurbID)

	cancelQueryID := &[thin.QueryIDLength]byte{}
	copy(cancelQueryID[:], []byte("cancel-query-001"))
	d.cancelResendingCopyCommand(&Request{
		AppID: appID,
		CancelResendingCopyCommand: &thin.CancelResendingCopyCommand{
			QueryID:      cancelQueryID,
			WriteCapHash: writeCapHash,
		},
	})

	// Drain the cancel-side response (ack to the original start query).
	select {
	case <-responseCh:
	default:
	}

	d.scheduleCopyCommandPoll(arqMessage)

	d.replyLock.Lock()
	defer d.replyLock.Unlock()

	_, oldPresent := d.arqSurbIDMap[*oldSurbID]
	require.False(t, oldPresent, "cancel should have cleared the old SURBID entry")
	require.Equal(t, 0, len(d.arqSurbIDMap), "schedule must not re-register after cancel")
	_, hashPresent := d.arqEnvelopeHashMap[*writeCapHash]
	require.False(t, hashPresent, "schedule must not re-register the envelope-hash entry after cancel")
}

// stubDaemonForHandleReply builds a Daemon with only the state
// handleReply touches: replyLock, the reply/decoy/ARQ maps, the
// ingress channel, and a started arq timer queue. A nil listener is
// NOT acceptable because handlePigeonholeARQReply dereferences it;
// caller can set it before calling handleReply.
func stubDaemonForHandleReply(t *testing.T) *Daemon {
	t.Helper()
	d := &Daemon{
		replies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:             make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:          new(sync.Mutex),
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		arqTimerQueue:      NewTimerQueue(func(_ interface{}) {}),
		log:                logging.MustGetLogger("test"),
	}
	d.arqTimerQueue.Start()
	t.Cleanup(func() { d.arqTimerQueue.Halt() })
	return d
}

// TestHandleReplyLeavesMapsIntactForARQReply pins the first arm of
// the new invariant: handleReply itself must NOT delete the ARQ map
// entries on receipt of an ARQ reply. Map transitions are henceforth
// the responsibility of the downstream handler (rotation on
// InProgress, deletion on terminal). The test drives handleReply for
// an arqMessage whose AppID has no registered connection — so the
// downstream handler exits at the no-conn guard without touching the
// maps — and asserts the arqMessage is still tracked after return.
func TestHandleReplyLeavesMapsIntactForARQReply(t *testing.T) {
	d, _, _ := newCancelRaceDaemon(t)

	// AppID the listener does NOT know about, so
	// handlePigeonholeARQReply's getConnection returns nil and it
	// early-exits without touching the maps.
	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("no-connection-00"))

	surbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(surbID[:], []byte("intact-srb-00001"))
	arqMessage, writeCapHash := installCopyARQ(d, unknownAppID, surbID)

	reply := &sphinxReply{
		surbID:     surbID,
		ciphertext: []byte("irrelevant — never decrypted because no conn"),
	}
	d.handleReply(reply)

	d.replyLock.Lock()
	defer d.replyLock.Unlock()

	msg, ok := d.arqSurbIDMap[*surbID]
	require.True(t, ok, "handleReply must not delete arqSurbIDMap for isARQReply")
	require.Same(t, arqMessage, msg)

	gotSurb, ok := d.arqEnvelopeHashMap[*writeCapHash]
	require.True(t, ok, "handleReply must not delete arqEnvelopeHashMap for isARQReply")
	require.Same(t, surbID, gotSurb)
}
