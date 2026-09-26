// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"net"
	"testing"
	"time"
)

func TestEventSinkWorkerStopsWhileFanningOutToAFullDrain(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tc := newHandshakeTestClient(t, client)
	drain := make(chan Event, 1)
	tc.Go(tc.eventSinkWorker)
	tc.drainAdd <- drain
	tc.eventSink <- &ConnectionStatusEvent{IsConnected: true}
	tc.eventSink <- &ConnectionStatusEvent{IsConnected: true}
	time.Sleep(100 * time.Millisecond)
	tc.Halt()
	time.Sleep(100 * time.Millisecond)
}

func TestWorkerStopsWhileReportingADisconnect(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	tc := newHandshakeTestClient(t, client)
	tc.eventSink = make(chan Event)
	tc.Go(tc.worker)
	server.Close()
	time.Sleep(100 * time.Millisecond)
	tc.Halt()
	time.Sleep(100 * time.Millisecond)
}
