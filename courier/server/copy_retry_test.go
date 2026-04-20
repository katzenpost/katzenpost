// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCopyAttemptBackoffMonotonic pins the doubling-then-cap shape of
// the Copy retry backoff so a refactor doesn't accidentally flatten it
// (hammering a struggling replica) or explode it (pinning the
// background goroutine for minutes).
func TestCopyAttemptBackoffMonotonic(t *testing.T) {
	require.Equal(t, 500*time.Millisecond, copyAttemptBackoff(0))
	require.Equal(t, 1*time.Second, copyAttemptBackoff(1))
	require.Equal(t, 2*time.Second, copyAttemptBackoff(2))
	require.Equal(t, 4*time.Second, copyAttemptBackoff(3))
	require.Equal(t, copyBackoffCap, copyAttemptBackoff(4))
	require.Equal(t, copyBackoffCap, copyAttemptBackoff(8))
	// Clamp: very large attempt counts do not overflow into an
	// unreasonable value.
	require.Equal(t, copyBackoffCap, copyAttemptBackoff(100))
}

// TestCopyRetryConstants guards the tunables the audit M1 fix relies
// on. Changing these affects worst-case Copy completion time.
func TestCopyRetryConstants(t *testing.T) {
	require.Equal(t, 3, maxCopyReadTransientAttempts)
	require.Equal(t, 5, maxCopyWriteAttempts)
	require.Equal(t, 500*time.Millisecond, copyBackoffBase)
	require.Equal(t, 5*time.Second, copyBackoffCap)
	require.Equal(t, 10*time.Second, copyReadReplyTimeout)
}

// TestCopySucceededReplyShape and TestCopyFailedReplyShape assert the
// terminal-reply helpers produce the exact wire shape the client
// daemon polls for.
func TestCopySucceededReplyShape(t *testing.T) {
	r := copySucceededReply()
	require.NotNil(t, r)
	require.NotNil(t, r.CopyCommandReply)
	require.Equal(t, uint8(1), r.ReplyType)
	require.Equal(t, uint8(0), r.CopyCommandReply.Status) // CopyStatusSucceeded
	require.Equal(t, uint8(0), r.CopyCommandReply.ErrorCode)
	require.Equal(t, uint64(0), r.CopyCommandReply.FailedEnvelopeIndex)
}

func TestCopyFailedReplyShape(t *testing.T) {
	r := copyFailedReply(42, 17)
	require.NotNil(t, r)
	require.NotNil(t, r.CopyCommandReply)
	require.Equal(t, uint8(1), r.ReplyType)
	require.Equal(t, uint8(2), r.CopyCommandReply.Status) // CopyStatusFailed
	require.Equal(t, uint8(42), r.CopyCommandReply.ErrorCode)
	require.Equal(t, uint64(17), r.CopyCommandReply.FailedEnvelopeIndex)
}
