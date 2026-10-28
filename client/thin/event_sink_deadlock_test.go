// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A caller that has its reply stops reading its sink and then calls
// StopEventSink, or EventSink for a follow-up request. If an event is
// already queued for its full sink, the fan-out must still serve the
// remove or add, or every caller on the connection stalls.
func TestEventSinkFanOutServesSinkChangesWhileBlocked(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tc := newTestThinClient(t, client)
	tc.Go(tc.eventSinkWorker)
	defer tc.Halt()

	other := tc.EventSink()
	stale := tc.EventSink()
	tc.eventSink <- &NewDocumentEvent{}
	<-other
	tc.eventSink <- &NewDocumentEvent{} // stale is full: the fan-out blocks on it

	done := make(chan chan Event)
	go func() {
		follow := tc.EventSink()
		tc.StopEventSink(stale)
		done <- follow
	}()
	var follow chan Event
	select {
	case follow = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("EventSink or StopEventSink hung behind a full sink")
	}

	// A sink added during a fan-out may also get the event in flight, so
	// each sink is read concurrently until the next event reaches it.
	tc.eventSink <- &ConnectionStatusEvent{IsConnected: true}
	got := make(chan bool, 2)
	for _, ch := range []chan Event{other, follow} {
		go func() {
			timeout := time.After(2 * time.Second)
			for {
				select {
				case ev := <-ch:
					if _, ok := ev.(*ConnectionStatusEvent); ok {
						got <- true
						return
					}
				case <-timeout:
					got <- false
					return
				}
			}
		}()
	}
	require.True(t, <-got, "events stopped flowing after the stale sink left")
	require.True(t, <-got, "events stopped flowing after the stale sink left")
}
