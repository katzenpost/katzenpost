// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/katzenpost/katzenpost/core/log"
)

func TestSender(t *testing.T) {
	rates := &Rates{
		messageOrLoop:         0.001,
		messageOrLoopMaxDelay: 1000,
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
