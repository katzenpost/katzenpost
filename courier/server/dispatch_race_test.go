// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// dispatchMessage runs on the dispatch worker goroutines while the
// connection worker rewrites c.dst on every reconnect
// (validateAndUpdateDescriptor). Reading c.dst.Name from dispatchMessage
// therefore races the descriptor pointer swap, which is exactly the
// condition on a link that keeps churning. Under -race the pre-fix code
// (c.dst.Name in dispatchMessage) trips the detector here; the fix reads
// the immutable c.name captured at construction, so this is clean.
func TestDispatchMessageNameNoRaceWithReconnect(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	c := &outgoingConn{
		log:    backendLog.GetLogger("test"),
		dst:    &cpki.ReplicaDescriptor{Name: "storagereplica0"},
		name:   "storagereplica0",
		sender: &sender{in: make(chan *courierSenderRequest, 8)},
	}

	// The connection worker swapping the descriptor on reconnect.
	done := make(chan struct{})
	go func() {
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			c.dst = &cpki.ReplicaDescriptor{Name: fmt.Sprintf("storagereplica%d", i%5)}
		}
	}()

	// The dispatch workers enqueueing while the descriptor churns. Both
	// the enqueue-success and the queue-full branches read the replica
	// name, so draining intermittently exercises both.
	for i := 0; i < 2000; i++ {
		_ = c.dispatchMessage(&commands.ReplicaMessage{})
		if i%2 == 0 {
			select {
			case <-c.sender.in:
			default:
			}
		}
	}
	close(done)
}
