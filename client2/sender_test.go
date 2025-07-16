// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"

	"github.com/katzenpost/katzenpost/core/log"
)

func TestSender(t *testing.T) {
	rates := &Rates{
		messageOrDrop:         0.001,
		messageOrDropMaxDelay: 1000,
		loop:                  0.0005,
		loopMaxDelay:          1000,
		drop:                  0.0005,
		dropMaxDelay:          3000,
	}

	in := make(chan *Request)
	out := make(chan *Request)
	logBackend, err := log.New("", "debug", false)
	if err != nil {
		t.FailNow()
	}

	s := newSender(in, out, false, logBackend)
	defer s.Halt()

	s.UpdateConnectionStatus(true)
	s.UpdateRates(rates)

	n := 10
	for i := 0; i < n; i++ {
		go func() {
			in <- &Request{}
		}()
	}

	for i := 0; i < n; i++ {
		t.Log("before out")
		s.UpdateRates(rates)
		r1 := <-s.out
		t.Log("after out")
		t.Logf("received request: %v", r1)
	}
}
