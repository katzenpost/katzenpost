// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestCacheEntryNeedsRedispatch(t *testing.T) {
	t.Parallel()

	e := &Courier{}
	errReply := &commands.ReplicaMessageReply{ErrorCode: 9}
	okReply := &commands.ReplicaMessageReply{ErrorCode: 0}

	require.False(t, e.cacheEntryNeedsRedispatch(nil))

	// Young and silent: still in flight, leave it alone.
	young := &CourierBookKeeping{CreatedAt: time.Now()}
	require.False(t, e.cacheEntryNeedsRedispatch(young))

	// Old and silent: the dispatch died with a session; re-dispatch.
	old := &CourierBookKeeping{CreatedAt: time.Now().Add(-2 * redispatchGrace)}
	require.True(t, e.cacheEntryNeedsRedispatch(old))

	// Errors only: re-dispatch regardless of age.
	errsOnly := &CourierBookKeeping{
		CreatedAt:       time.Now(),
		EnvelopeReplies: [2]*commands.ReplicaMessageReply{errReply, nil},
	}
	require.True(t, e.cacheEntryNeedsRedispatch(errsOnly))

	// Any success: never re-dispatch.
	success := &CourierBookKeeping{
		CreatedAt:       time.Now().Add(-2 * redispatchGrace),
		EnvelopeReplies: [2]*commands.ReplicaMessageReply{errReply, okReply},
	}
	require.False(t, e.cacheEntryNeedsRedispatch(success))

	// Exhausted attempt budget: never re-dispatch.
	exhausted := &CourierBookKeeping{
		CreatedAt:          time.Now().Add(-2 * redispatchGrace),
		RedispatchAttempts: maxRedispatchAttempts,
	}
	require.False(t, e.cacheEntryNeedsRedispatch(exhausted))
}
