// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func newTestDaemon(bufSize int) *Daemon {
	d := &Daemon{
		arqResendCh: make(chan *[sphinxConstants.SURBIDLength]byte, bufSize),
		log:         logging.MustGetLogger("test"),
	}
	return d
}

// TestARQResendNeverDrops verifies the correct behavior: all resends
// must be delivered, none dropped, regardless of concurrency.
// Uses a small buffer (2) to prove resends block instead of dropping.
func TestARQResendNeverDrops(t *testing.T) {
	d := newTestDaemon(2)

	numResends := 100
	var received atomic.Int32

	// Drain the channel in a goroutine
	done := make(chan struct{})
	go func() {
		for range d.arqResendCh {
			received.Add(1)
			if int(received.Load()) == numResends {
				close(done)
				return
			}
		}
	}()

	// Fire 100 concurrent resends — all must arrive
	var wg sync.WaitGroup
	for i := 0; i < numResends; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			surbID := new([sphinxConstants.SURBIDLength]byte)
			surbID[0] = byte(id)
			d.arqResend(surbID)
		}(i)
	}

	wg.Wait()

	// Wait for all to be drained, with timeout
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("Timed out: sent %d resends, only %d received", numResends, received.Load())
	}

	require.Equal(t, numResends, int(received.Load()), "All resends must be delivered, none dropped")
}

// TestARQResendHalts verifies that arqResend returns promptly when Halt is called,
// even if the channel is full.
func TestARQResendHalts(t *testing.T) {
	d := newTestDaemon(1)

	// Fill the buffer
	surbID1 := new([sphinxConstants.SURBIDLength]byte)
	d.arqResendCh <- surbID1

	// Now the channel is full. arqResend should block until halt.
	done := make(chan struct{})
	go func() {
		surbID2 := new([sphinxConstants.SURBIDLength]byte)
		surbID2[0] = 1
		d.arqResend(surbID2)
		close(done)
	}()

	// Should not complete yet
	select {
	case <-done:
		t.Fatal("arqResend returned before halt was called")
	case <-time.After(100 * time.Millisecond):
	}

	// Halt should unblock it
	d.Halt()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("arqResend did not return after Halt")
	}
}

// Ensure Daemon embeds worker.Worker for HaltCh support
var _ interface{ HaltCh() <-chan interface{} } = &Daemon{}
