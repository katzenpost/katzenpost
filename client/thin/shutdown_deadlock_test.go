// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEventSinkRegistrationDoesNotHangAfterHalt(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tc := newHandshakeTestClient(t, client)
	tc.Go(tc.eventSinkWorker)
	sink := tc.EventSink()
	tc.Halt()

	done := make(chan struct{})
	go func() {
		tc.StopEventSink(sink)
		tc.EventSink()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "event sink registration blocked after Halt")
	}
}
