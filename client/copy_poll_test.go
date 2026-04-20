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

// TestScheduleCopyCommandPollReRegistersForCancellation pins the core
// invariant the daemon's InProgress polling must maintain: the
// ARQMessage stays reachable by its EnvelopeHash between receiving an
// InProgress reply and the next scheduled poll send, so
// CancelResendingCopyCommand can still find and drop the operation.
func TestScheduleCopyCommandPollReRegistersForCancellation(t *testing.T) {
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

	// Simulate handleReply's cleanup: both maps emptied before the
	// Copy-reply dispatcher runs. scheduleCopyCommandPoll must restore
	// a hash→surbID mapping so Cancel still works.
	d.scheduleCopyCommandPoll(arqMessage)

	// After scheduling, EnvelopeHash must resolve to a placeholder
	// SURB ID that in turn resolves to the same ARQMessage.
	d.replyLock.Lock()
	placeholder, ok := d.arqEnvelopeHashMap[*envHash]
	require.True(t, ok, "envelope hash must be re-registered")
	require.NotEqual(t, *oldSurbID, *placeholder, "placeholder must differ from pre-cleanup SURBID")

	msg, ok := d.arqSurbIDMap[*placeholder]
	require.True(t, ok, "placeholder SURBID must be in arqSurbIDMap")
	require.Same(t, arqMessage, msg)
	d.replyLock.Unlock()

	// The ARQMessage's SURBID field should also be updated to the
	// placeholder so a subsequent arqDoResend finds the correct entry.
	require.Equal(t, placeholder, arqMessage.SURBID)
}

// TestCopyPollIntervalConstant pins the polling cadence so a refactor
// doesn't silently change it. Five seconds is frequent enough to keep
// latency low for small Copies and sparse enough not to hammer the
// courier.
func TestCopyPollIntervalConstant(t *testing.T) {
	require.Equal(t, 5*time.Second, CopyPollInterval)
}
