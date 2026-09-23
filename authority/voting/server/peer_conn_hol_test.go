// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// TestDoSendCommandNoCrossPhaseHeadOfLineBlock proves a later phase's send does
// not stall behind a slow send already in flight on the cached connection. The
// per-peer mutex is shared across all voting phases; if a send holds it across
// the network round trip, a second send blocks at the lock until the first
// finishes, which can blow the later phase's deadline. The second send must
// make progress (via a one-shot connection) instead of queueing behind the
// stuck one.
func TestDoSendCommandNoCrossPhaseHeadOfLineBlock(t *testing.T) {
	require := require.New(t)
	const wireKEM = "Xwing"

	sender, senderID, _ := mkAuthState(t, "sender", wireKEM)
	responder, respID, respLink := mkAuthState(t, "responder", wireKEM)

	sh := hash.Sum256From(senderID)
	rh := hash.Sum256From(respID)
	responder.authorizedAuthorities[sh] = true
	sender.authorizedAuthorities[rh] = true

	kemScheme := kemschemes.ByName(wireKEM)
	respCfg := &wire.SessionConfig{
		KEMScheme:         kemScheme,
		Authenticator:     responder,
		AdditionalData:    rh[:],
		AuthenticationKey: respLink,
		RandomReader:      rand.Reader,
	}
	sender.dialContextFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
		cli, srvConn := net.Pipe()
		go func() {
			rs, err := wire.NewPKISession(respCfg, false)
			if err != nil {
				srvConn.Close()
				return
			}
			if err := rs.Initialize(context.Background(), srvConn); err != nil {
				srvConn.Close()
				return
			}
			responder.s.serveAuthorityConn(srvConn, rs, "sender", nil)
		}()
		return cli, nil
	}

	peer := &config.Authority{Identifier: "responder", Addresses: []string{"tcp://127.0.0.1:1"}}

	// Simulate a slow send already in flight in an earlier phase: hold the
	// per-peer lock for the whole test.
	pc := sender.peerConnFor(peer.Identifier)
	pc.mu.Lock()
	defer pc.mu.Unlock()

	epoch, _, _ := epochtime.Now()
	done := make(chan error, 1)
	go func() {
		resp, err := sender.doSendCommand(peer, &commands.GetConsensus{Epoch: epoch + 1, Cmds: commands.NewPKICommands(nil)}, peer.Addresses)
		if err != nil {
			done <- err
			return
		}
		if _, ok := resp.(*commands.Consensus); !ok {
			done <- context.DeadlineExceeded
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		require.NoError(err, "a later-phase send must not block on an in-flight send holding the peer lock")
	case <-time.After(10 * time.Second):
		t.Fatal("doSendCommand blocked on the per-peer lock held by another phase")
	}
}
