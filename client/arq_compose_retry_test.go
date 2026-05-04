// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// TestRescheduleARQAfterComposeFailureRotatesMaps covers the arqDoResend
// call shape: the message is still keyed in arqSurbIDMap under the SURBID
// whose timer just fired, and rescheduleARQAfterComposeFailure is expected
// to delete that stale key, insert a fresh placeholder, update both maps,
// and push the placeholder onto arqTimerQueue for a later retry.
func TestRescheduleARQAfterComposeFailureRotatesMaps(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		replyLock:          new(sync.Mutex),
		log:                logging.MustGetLogger("test"),
		arqTimerQueue:      NewTimerQueue(func(interface{}) {}),
	}

	oldSurbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(oldSurbID[:], []byte("old-surbid-00001"))
	envHash := &[32]byte{}
	copy(envHash[:], []byte("envelope-hash-exactly-32-bytes!!"))

	arqMessage := &ARQMessage{
		EnvelopeHash: envHash,
		SURBID:       oldSurbID,
	}
	d.arqSurbIDMap[*oldSurbID] = arqMessage
	d.arqEnvelopeHashMap[*envHash] = oldSurbID

	d.rescheduleARQAfterComposeFailure(arqMessage)

	d.replyLock.Lock()
	defer d.replyLock.Unlock()

	require.NotContains(t, d.arqSurbIDMap, *oldSurbID,
		"stale SURBID key must be removed from arqSurbIDMap")
	require.NotEqual(t, oldSurbID, arqMessage.SURBID,
		"ARQMessage.SURBID must be rotated to a fresh placeholder")

	newSurbID := arqMessage.SURBID
	require.NotNil(t, newSurbID)
	require.Same(t, arqMessage, d.arqSurbIDMap[*newSurbID],
		"placeholder SURBID must resolve to the ARQMessage")
	require.Equal(t, newSurbID, d.arqEnvelopeHashMap[*envHash],
		"arqEnvelopeHashMap must point to the new placeholder SURBID")

	// The pushCh entry proves the retry was queued; we cannot inspect the
	// internal heap without starting the worker.
	require.Equal(t, 1, len(d.arqTimerQueue.pushCh),
		"retry must be pushed onto arqTimerQueue, not silently dropped")
}

// TestRescheduleARQAfterComposeFailureWithDeletedMapEntry covers the
// handlePigeonholeARQReply / handlePayloadReply call shape: by the time
// the retry branch runs, handleReply has already deleted the prior SURBID
// from arqSurbIDMap and arqEnvelopeHashMap. The helper must tolerate the
// missing old entry and still register the placeholder and timer.
func TestRescheduleARQAfterComposeFailureWithDeletedMapEntry(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		replyLock:          new(sync.Mutex),
		log:                logging.MustGetLogger("test"),
		arqTimerQueue:      NewTimerQueue(func(interface{}) {}),
	}

	staleSurbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(staleSurbID[:], []byte("stale-surbid-0001"))
	envHash := &[32]byte{}
	copy(envHash[:], []byte("envelope-hash-exactly-32-bytes!!"))

	// Simulate the post-handleReply state: arqMessage.SURBID still points
	// at the stale ID, but the maps no longer contain it.
	arqMessage := &ARQMessage{
		EnvelopeHash: envHash,
		SURBID:       staleSurbID,
	}

	d.rescheduleARQAfterComposeFailure(arqMessage)

	d.replyLock.Lock()
	defer d.replyLock.Unlock()

	require.NotEqual(t, staleSurbID, arqMessage.SURBID,
		"SURBID must be rotated to a fresh placeholder even when the old key was absent")
	require.Same(t, arqMessage, d.arqSurbIDMap[*arqMessage.SURBID])
	require.Equal(t, arqMessage.SURBID, d.arqEnvelopeHashMap[*envHash])
	require.Equal(t, 1, len(d.arqTimerQueue.pushCh),
		"retry must be pushed onto arqTimerQueue")
}

// TestRescheduleARQAfterComposeFailureNilEnvelopeHash guards against a
// panic if an ARQMessage without an EnvelopeHash reaches the helper.
func TestRescheduleARQAfterComposeFailureNilEnvelopeHash(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		replyLock:          new(sync.Mutex),
		log:                logging.MustGetLogger("test"),
		arqTimerQueue:      NewTimerQueue(func(interface{}) {}),
	}

	arqMessage := &ARQMessage{EnvelopeHash: nil, SURBID: nil}

	require.NotPanics(t, func() {
		d.rescheduleARQAfterComposeFailure(arqMessage)
	})

	d.replyLock.Lock()
	defer d.replyLock.Unlock()

	require.NotNil(t, arqMessage.SURBID)
	require.Same(t, arqMessage, d.arqSurbIDMap[*arqMessage.SURBID])
	require.Empty(t, d.arqEnvelopeHashMap,
		"no envelope-hash entries must be created when EnvelopeHash is nil")
}
