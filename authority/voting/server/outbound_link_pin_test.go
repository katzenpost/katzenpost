// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestOutboundSessionPinsDialledAuthority(t *testing.T) {
	const wireKEM = "Xwing"
	sender, senderID, _ := mkAuthStateScheme(t, "sender", wireKEM, testSchemeName)
	responder, respID, respLink := mkAuthStateScheme(t, "responder", wireKEM, testSchemeName)
	_, otherID, otherLink := mkAuthStateScheme(t, "other", wireKEM, testSchemeName)
	sh := hash.Sum256From(senderID)
	rh := hash.Sum256From(respID)
	oh := hash.Sum256From(otherID)
	responder.authorizedAuthorities[sh] = true
	sender.authorizedAuthorities[rh] = true
	sender.authorizedAuthorities[oh] = true
	sender.s.cfg.Server.PersistentPeerConns = false

	peer := &config.Authority{
		Identifier:        "responder",
		IdentityPublicKey: respID,
		LinkPublicKey:     config.LinkPublicKey{PublicKey: respLink.Public()},
		Addresses:         []string{"tcp://127.0.0.1:1"},
	}
	epoch, _, _ := epochtime.Now()

	for _, c := range []struct {
		name string
		ad   [publicKeyHashSize]byte
		link kem.PrivateKey
		ok   bool
	}{
		{"another authority's identity", oh, otherLink, false},
		{"dialled identity with another link key", rh, otherLink, false},
		{"dialled authority", rh, respLink, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			respCfg := &wire.SessionConfig{
				KEMScheme:          kemschemes.ByName(wireKEM),
				PKISignatureScheme: signschemes.ByName(testSchemeName),
				Authenticator:      responder,
				AdditionalData:     c.ad[:],
				AuthenticationKey:  c.link,
				RandomReader:       rand.Reader,
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
			resp, err := sender.doSendCommand(peer, &commands.GetConsensus{Epoch: epoch + 1, Cmds: commands.NewPKICommands(nil)}, peer.Addresses)
			if !c.ok {
				require.Error(t, err)
				require.Nil(t, resp)
				return
			}
			require.NoError(t, err)
			_, isConsensus := resp.(*commands.Consensus)
			require.True(t, isConsensus, "got %T", resp)
		})
	}
}
