// SPDX-License-Identifier: AGPL-3.0-only

package wire

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// TestConcurrentSendCommandNonceRace drives two goroutines sending on one
// session at once. SendCommand advances the tx cipher's nonce counter, which is
// a mutating operation; guarding it with a shared (read) lock lets the two
// senders race that counter and reuse a ChaChaPoly nonce, which is fatal. This
// test only detects the hazard under the race detector (go test -race); the fix
// switches the cipher-state mutexes from RWMutex to plain Mutex.
func TestConcurrentSendCommandNonceRace(t *testing.T) {
	alice, bob := deadlineTestConfigs(t)
	sA, sB, cA, cB := establishTestPair(t, alice, bob)
	defer sA.Close()
	defer sB.Close()
	defer cA.Close()
	defer cB.Close()

	// Drain the wire so the concurrent writes never block on the pipe.
	go io.Copy(io.Discard, cB)

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = sA.SendCommand(context.Background(), &commands.NoOp{Cmds: sA.commands})
			}
		}()
	}
	wg.Wait()
}
