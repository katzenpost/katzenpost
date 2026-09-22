// SPDX-License-Identifier: AGPL-3.0-only

package wire

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

var errUnexpectedCmd = errors.New("peer decoded an unexpected command type")

// TestConcurrentSendCommandStreamIntegrity drives two goroutines sending on one
// Session at once while the peer decodes every frame. A logical send is header
// encrypt + body encrypt + rekey; if those steps are not serialized as a unit,
// two senders interleave their cipher operations and the tx nonce/rekey stream
// desynchronizes from what the receiver expects, so a later frame fails its MAC
// and RecvCommand errors. Guarding each individual cipher op (the old behavior)
// is not enough: only holding one exclusive lock across the whole logical send
// (and the wire write) keeps the stream decodable. Red is probabilistic but
// near-certain at this frame count without the fix.
func TestConcurrentSendCommandStreamIntegrity(t *testing.T) {
	alice, bob := deadlineTestConfigs(t)
	sA, sB, cA, cB := establishTestPair(t, alice, bob)
	defer sA.Close()
	defer sB.Close()
	defer cA.Close()
	defer cB.Close()

	const senders = 2
	const perSender = 150
	total := senders * perSender

	recvErr := make(chan error, 1)
	go func() {
		for i := 0; i < total; i++ {
			cmd, err := sB.RecvCommand(context.Background())
			if err != nil {
				recvErr <- err
				return
			}
			if _, ok := cmd.(*commands.NoOp); !ok {
				recvErr <- errUnexpectedCmd
				return
			}
		}
		recvErr <- nil
	}()

	var wg sync.WaitGroup
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perSender; j++ {
				if err := sA.SendCommand(context.Background(), &commands.NoOp{Cmds: sA.commands}); err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()

	require.NoError(t, <-recvErr, "peer failed to decode a frame: concurrent sends corrupted the cipher stream")
}
