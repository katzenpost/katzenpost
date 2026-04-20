// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// TestRotateARQSurbIDLockedKeepsEnvelopeHashMapping is the regression test
// for the bug where handlePigeonholeARQReply's SendNewSURB branch updated
// arqSurbIDMap to point to a newly rotated SURB ID but left
// arqEnvelopeHashMap pointing at the old (now-deleted) SURB ID.
//
// The symptom was that CancelResendingEncryptedMessage silently no-op'd
// for any ARQ operation that had passed the first courier ACK — i.e.
// reads, and non-idempotent writes waiting for the replica payload —
// while the ARQ timer kept retransmitting forever.
//
// After rotation, both maps MUST agree on the ARQMessage's current SURB ID.
func TestRotateARQSurbIDLockedKeepsEnvelopeHashMapping(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		replyLock:          new(sync.Mutex),
		log:                logging.MustGetLogger("test"),
	}

	oldSurbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(oldSurbID[:], []byte("old-surbid-00001"))
	newSurbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(newSurbID[:], []byte("new-surbid-00002"))

	envHash := &[32]byte{}
	copy(envHash[:], []byte("envelope-hash-exactly-32-bytes!!"))

	arqMessage := &ARQMessage{
		EnvelopeHash:    envHash,
		SURBID:          oldSurbID,
		Retransmissions: 7,
	}

	// Reflects the state SendNewSURB runs in: handleReply (daemon.go)
	// preemptively deletes both map entries for an ARQ reply before the
	// FSM dispatches, so we start from empty maps.
	surbKey := []byte("fake-surb-key")
	rtt := 5 * time.Second

	d.replyLock.Lock()
	d.rotateARQSurbIDLocked(arqMessage, newSurbID, surbKey, rtt)
	d.replyLock.Unlock()

	d.replyLock.Lock()
	defer d.replyLock.Unlock()

	// ARQMessage fields updated.
	require.Equal(t, newSurbID, arqMessage.SURBID, "SURBID should be updated")
	require.Equal(t, surbKey, arqMessage.SURBDecryptionKeys, "SURB decryption keys should be updated")
	require.Equal(t, rtt, arqMessage.ReplyETA, "ReplyETA should be updated")
	require.Equal(t, uint32(8), arqMessage.Retransmissions, "Retransmissions should be incremented")

	// arqSurbIDMap swings to the new SURB ID.
	require.Same(t, arqMessage, d.arqSurbIDMap[*newSurbID], "arqSurbIDMap should map newSurbID to arqMessage")
	require.NotContains(t, d.arqSurbIDMap, *oldSurbID, "arqSurbIDMap should not retain oldSurbID")

	// The H2 regression check: cancellation by EnvelopeHash must still find
	// the message after a reply-driven SURB rotation.
	storedSurbID, found := d.arqEnvelopeHashMap[*envHash]
	require.True(t, found, "arqEnvelopeHashMap must contain the envelope hash after rotation")
	require.Equal(t, newSurbID, storedSurbID, "arqEnvelopeHashMap should point to the new SURB ID")
}

// TestRotateARQSurbIDLockedNilEnvelopeHash verifies the helper handles an
// ARQMessage with a nil EnvelopeHash without panicking or creating a
// spurious map entry. Not every ARQMessage carries an EnvelopeHash.
func TestRotateARQSurbIDLockedNilEnvelopeHash(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		replyLock:          new(sync.Mutex),
		log:                logging.MustGetLogger("test"),
	}

	oldSurbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(oldSurbID[:], []byte("old-surbid-00001"))
	newSurbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(newSurbID[:], []byte("new-surbid-00002"))

	arqMessage := &ARQMessage{
		EnvelopeHash: nil,
		SURBID:       oldSurbID,
	}

	d.replyLock.Lock()
	d.rotateARQSurbIDLocked(arqMessage, newSurbID, []byte("k"), time.Second)
	d.replyLock.Unlock()

	d.replyLock.Lock()
	defer d.replyLock.Unlock()

	require.Equal(t, newSurbID, arqMessage.SURBID)
	require.Same(t, arqMessage, d.arqSurbIDMap[*newSurbID])
	require.Empty(t, d.arqEnvelopeHashMap, "no envelope-hash entries should be created when EnvelopeHash is nil")
}

// TestRotateARQSurbIDLockedCancelAfterRotation exercises the same flow
// CancelResendingEncryptedMessage uses: look up the EnvelopeHash, find the
// current SURB ID, and retrieve the ARQMessage from arqSurbIDMap. This is
// the consumer-side assertion that the maps remain consistent through a
// reply-driven rotation.
func TestRotateARQSurbIDLockedCancelAfterRotation(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		replyLock:          new(sync.Mutex),
		log:                logging.MustGetLogger("test"),
	}

	oldSurbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(oldSurbID[:], []byte("old-surbid-00001"))
	newSurbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(newSurbID[:], []byte("new-surbid-00002"))
	envHash := &[32]byte{}
	copy(envHash[:], []byte("envelope-hash-exactly-32-bytes!!"))

	arqMessage := &ARQMessage{
		EnvelopeHash: envHash,
		SURBID:       oldSurbID,
	}

	d.replyLock.Lock()
	d.rotateARQSurbIDLocked(arqMessage, newSurbID, []byte("k"), time.Second)
	d.replyLock.Unlock()

	// Simulate CancelResendingEncryptedMessage's lookup path.
	d.replyLock.Lock()
	surbIDFromHash, ok := d.arqEnvelopeHashMap[*envHash]
	require.True(t, ok, "cancel-by-envelope-hash lookup must succeed after rotation")

	foundMessage, ok := d.arqSurbIDMap[*surbIDFromHash]
	require.True(t, ok, "resolving the mapped SURB ID must find the ARQMessage")
	require.Same(t, arqMessage, foundMessage)
	d.replyLock.Unlock()
}
