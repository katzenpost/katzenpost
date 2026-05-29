// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
)

func TestSenderUpdateRatesInvalid(t *testing.T) {
	out := make(chan *Request)
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	pickNext := func() *Request { return nil }
	s := newSender(pickNext, out, false, logBackend)
	defer s.Halt()

	// Zero rate should not panic, just log warning
	s.UpdateRates(&Rates{messageOrLoop: 0})

	// Negative rate should not panic
	s.UpdateRates(&Rates{messageOrLoop: -1})
}

// TestSenderDecoysDisabledRateUpdatesDoNotWedge is a regression guard for
// the deadlock in which, with decoys disabled, the sender muted its read of
// sendLoop.OutCh yet still drove the sendLoop ExpDist. The driven-but-undrained
// ExpDist worker blocked emitting to its OutCh, which then blocked UpdateRate;
// because UpdateRate runs on the PKI-document broadcast path, that backpressure
// wedged the PKI worker and froze the daemon's consensus fetches. The sendLoop
// must therefore stay dormant while decoys are disabled.
func TestSenderDecoysDisabledRateUpdatesDoNotWedge(t *testing.T) {
	out := make(chan *Request, 16)
	stop := make(chan struct{})
	// Drain egress so the always-on sendMessageOrLoop path never backs up;
	// this test targets the sendLoop/disableDecoys path specifically.
	go func() {
		for {
			select {
			case <-out:
			case <-stop:
				return
			}
		}
	}()
	defer close(stop)

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	s := newSender(func() *Request { return nil }, out, true /* disableDecoys */, logBackend)
	defer s.Halt()

	s.UpdateConnectionStatus(true)

	done := make(chan struct{})
	go func() {
		// A 1ms mean loop rate makes a (wrongly) driven sendLoop ExpDist
		// fire and fill its buffers within milliseconds; the repeated
		// updates then block once it wedges. With sendLoop kept dormant
		// these calls never touch it and return promptly.
		for i := 0; i < 100; i++ {
			s.UpdateRates(&Rates{messageOrLoop: 1.0, loop: 1.0})
			time.Sleep(3 * time.Millisecond)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("UpdateRates wedged with decoys disabled: the loop-decoy ExpDist was driven but its OutCh is never drained")
	}
}

func TestNewLoopDecoy(t *testing.T) {
	req := newLoopDecoy()
	require.NotNil(t, req)
	require.NotNil(t, req.SendLoopDecoy)
	require.Nil(t, req.SendMessage)
	require.Nil(t, req.NewKeypair)
}
