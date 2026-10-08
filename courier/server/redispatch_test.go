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

	errsOnly := &CourierBookKeeping{
		CreatedAt:       time.Now().Add(-2 * redispatchGrace),
		EnvelopeReplies: [2]*commands.ReplicaMessageReply{errReply, nil},
	}
	require.True(t, e.cacheEntryNeedsRedispatch(errsOnly))

	spentTooSoon := &CourierBookKeeping{
		CreatedAt:          time.Now().Add(-2 * redispatchGrace),
		RedispatchAttempts: 2,
		EnvelopeReplies:    [2]*commands.ReplicaMessageReply{errReply, nil},
	}
	require.False(t, e.cacheEntryNeedsRedispatch(spentTooSoon),
		"attempt %d must wait %s from creation, not fire on the next poll",
		spentTooSoon.RedispatchAttempts+1, redispatchGrace*time.Duration(spentTooSoon.RedispatchAttempts+1))

	spacedOut := &CourierBookKeeping{
		CreatedAt:          time.Now().Add(-4 * redispatchGrace),
		RedispatchAttempts: 2,
		EnvelopeReplies:    [2]*commands.ReplicaMessageReply{errReply, nil},
	}
	require.True(t, e.cacheEntryNeedsRedispatch(spacedOut),
		"attempt %d is due once %s have passed since creation",
		spacedOut.RedispatchAttempts+1, redispatchGrace*time.Duration(spacedOut.RedispatchAttempts+1))

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

func TestCacheEntryRedispatchPacing(t *testing.T) {
	t.Parallel()

	e := &Courier{}
	errReply := &commands.ReplicaMessageReply{ErrorCode: 9}
	aged := func(n float64, attempts int, replies [2]*commands.ReplicaMessageReply) *CourierBookKeeping {
		return &CourierBookKeeping{
			CreatedAt:          time.Now().Add(-time.Duration(n * float64(redispatchGrace))),
			RedispatchAttempts: attempts,
			EnvelopeReplies:    replies,
		}
	}
	errs := [2]*commands.ReplicaMessageReply{errReply, errReply}
	silent := [2]*commands.ReplicaMessageReply{}

	require.False(t, e.cacheEntryNeedsRedispatch(aged(0, 0, errs)))
	require.False(t, e.cacheEntryNeedsRedispatch(aged(0.9, 0, errs)))
	require.True(t, e.cacheEntryNeedsRedispatch(aged(1.1, 0, errs)))

	require.False(t, e.cacheEntryNeedsRedispatch(aged(1.5, 1, silent)))
	require.True(t, e.cacheEntryNeedsRedispatch(aged(2.5, 1, silent)))

	last := maxRedispatchAttempts - 1
	require.False(t, e.cacheEntryNeedsRedispatch(aged(float64(last)+0.9, last, errs)))
	require.True(t, e.cacheEntryNeedsRedispatch(aged(float64(last)+1.1, last, errs)))
	require.False(t, e.cacheEntryNeedsRedispatch(aged(100, maxRedispatchAttempts, errs)))
}
