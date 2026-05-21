// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
)

// TestSender drives the LambdaP ticker end-to-end with a queued FIFO
// of real requests. It also publishes a LambdaL rate so the LambdaL
// ticker fires loop decoys concurrently; both kinds of emission land
// on the same out channel.
func TestSender(t *testing.T) {
	rates := &Rates{
		messageOrLoop:         0.001,
		loop:                  0.001,
	}

	in := make(chan *Request, 10)
	out := make(chan *Request)
	logBackend, err := log.New("", "debug", false)
	if err != nil {
		t.FailNow()
	}

	// A simple pickNext that drains a channel, simulating the listener's
	// scheduler for this end-to-end timer-driven test.
	pickNext := func() *Request {
		select {
		case r := <-in:
			return r
		default:
			return nil
		}
	}

	s := newSender(pickNext, out, false, logBackend)
	defer s.Halt()

	s.UpdateConnectionStatus(true)
	s.UpdateRates(rates)

	n := 10
	for i := 0; i < n; i++ {
		in <- &Request{}
	}

	for i := 0; i < n; i++ {
		t.Log("before out")
		s.UpdateRates(rates)
		r1 := <-s.out
		t.Log("after out")
		t.Logf("received request: %v", r1)
	}
}

// TestSenderLambdaLOnly exercises the LambdaL ticker in isolation
// with no real work queued and decoys enabled. Every emission must
// be a loop decoy.
func TestSenderLambdaLOnly(t *testing.T) {
	out := make(chan *Request, 4)
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	pickNext := func() *Request { return nil }
	s := newSender(pickNext, out, false, logBackend)
	defer s.Halt()

	s.UpdateConnectionStatus(true)
	s.UpdateRates(&Rates{
		messageOrLoop:         0.001,
		loop:                  0.01,
	})

	for i := 0; i < 4; i++ {
		req := <-out
		require.NotNil(t, req.SendLoopDecoy)
	}
}
