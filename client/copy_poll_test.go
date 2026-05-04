// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// TestScheduleCopyCommandPollRotationKeepsEnvelopeHashLive pins the
// rotation invariant after the cancel-race fix: when a Copy
// InProgress reply reaches scheduleCopyCommandPoll, the ARQMessage is
// still tracked in both maps (handleReply no longer pre-deletes), and
// the schedule performs an atomic rotation — remove the old SURBID
// entry, install the new placeholder in both maps, update
// arqMessage.SURBID. The EnvelopeHash thus stays reachable across the
// rotation so CancelResendingCopyCommand can always find and drop the
// operation.
func TestScheduleCopyCommandPollRotationKeepsEnvelopeHashLive(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		arqTimerQueue:      NewTimerQueue(func(_ interface{}) {}),
		replyLock:          new(sync.Mutex),
		log:                logging.MustGetLogger("test"),
	}
	d.arqTimerQueue.Start()
	defer d.arqTimerQueue.Halt()

	envHash := &[32]byte{}
	copy(envHash[:], []byte("copy-cmd-writecap-hash-32-bytes!"))

	oldSurbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(oldSurbID[:], []byte("old-surbid-00001"))

	arqMessage := &ARQMessage{
		MessageType:  ARQMessageTypeCopyCommand,
		EnvelopeHash: envHash,
		SURBID:       oldSurbID,
		Payload:      []byte("copy-command-payload"),
	}

	// Post-handleReply state: the arqMessage is still tracked under
	// its current SURBID (handleReply no longer pre-deletes).
	d.replyLock.Lock()
	d.arqSurbIDMap[*oldSurbID] = arqMessage
	d.arqEnvelopeHashMap[*envHash] = oldSurbID
	d.replyLock.Unlock()

	d.scheduleCopyCommandPoll(arqMessage)

	d.replyLock.Lock()
	defer d.replyLock.Unlock()

	_, oldStillPresent := d.arqSurbIDMap[*oldSurbID]
	require.False(t, oldStillPresent, "old SURBID entry must be rotated out")

	placeholder, ok := d.arqEnvelopeHashMap[*envHash]
	require.True(t, ok, "envelope hash must remain registered across rotation")
	require.NotEqual(t, *oldSurbID, *placeholder, "placeholder must differ from old SURBID")

	msg, ok := d.arqSurbIDMap[*placeholder]
	require.True(t, ok, "placeholder SURBID must be in arqSurbIDMap")
	require.Same(t, arqMessage, msg)

	require.Equal(t, placeholder, arqMessage.SURBID)
}

// TestCopyPollIntervalConstant pins the polling cadence so a refactor
// doesn't silently change it. Five seconds is frequent enough to keep
// latency low for small Copies and sparse enough not to hammer the
// courier.
func TestCopyPollIntervalConstant(t *testing.T) {
	require.Equal(t, 5*time.Second, CopyPollInterval)
}
