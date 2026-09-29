// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// panicOnDeadlineConn is a net.Conn whose SetDeadline panics. peerRoundTrip
// calls conn.SetDeadline before touching the session, so a cached conn like this
// makes a reused round trip panic.
type panicOnDeadlineConn struct{ net.Conn }

func (panicOnDeadlineConn) SetDeadline(time.Time) error { panic("boom in round trip") }

// TestDoSendCommandEvictsCachedConnOnPanic proves a panic during a reused
// persistent-connection round trip still evicts the cached session. The
// outbound send recovers from the panic and returns an error, but before the
// fix it skipped the pc.closeLocked() eviction that every normal error path
// performs, leaving a possibly-corrupted session cached for the next reuse.
func TestDoSendCommandEvictsCachedConnOnPanic(t *testing.T) {
	require := require.New(t)
	const wireKEM = "Xwing"

	sender, _, linkPriv := mkAuthState(t, "sender", wireKEM)

	// A non-nil session so doSendCommand takes the reuse branch. It is never
	// driven: the cached conn's SetDeadline panics first.
	kemScheme := kemschemes.ByName(wireKEM)
	sess, err := wire.NewPKISession(&wire.SessionConfig{
		KEMScheme:         kemScheme,
		Authenticator:     sender,
		AdditionalData:    []byte("sender"),
		AuthenticationKey: linkPriv,
		RandomReader:      rand.Reader,
	}, true)
	require.NoError(err)

	peer := &config.Authority{Identifier: "responder", Addresses: []string{"tcp://127.0.0.1:1"}}

	pc := sender.peerConnFor(peer.Identifier)
	pc.session = sess
	pc.conn = panicOnDeadlineConn{}

	epoch, _, _ := epochtime.Now()
	resp, err := sender.doSendCommand(peer, &commands.GetConsensus{Epoch: epoch + 1, Cmds: commands.NewPKICommands(nil)}, peer.Addresses)
	require.Error(err, "a panic in the round trip must surface as an error")
	require.Nil(resp)

	pc.mu.Lock()
	cached := pc.session
	pc.mu.Unlock()
	require.Nil(cached, "a panic during a reused round trip must evict the cached session")
}
