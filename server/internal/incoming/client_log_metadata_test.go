// SPDX-License-Identifier: AGPL-3.0-only

package incoming

import (
	"container/list"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/spool"
)

type acceptAll struct{}

func (acceptAll) IsPeerValid(*wire.PeerCredentials) bool { return true }

type clientOnlyPKI struct{ glue.PKI }

func (clientOnlyPKI) AuthenticateConnection(*wire.PeerCredentials, bool) (*pki.MixDescriptor, bool, bool) {
	return nil, false, false
}

type emptySpool struct{ spool.Spool }

func (emptySpool) Get([]byte, bool) ([]byte, []byte, int, error) {
	return nil, nil, 0, errors.New("empty")
}

type clientGateway struct{ glue.Gateway }

func (clientGateway) AuthenticateClient(*wire.PeerCredentials) bool { return true }
func (clientGateway) Spool() spool.Spool                            { return emptySpool{} }

type clientLogGlue struct {
	*capGlue
}

func (g *clientLogGlue) PKI() glue.PKI              { return clientOnlyPKI{} }
func (g *clientLogGlue) Gateway() glue.Gateway      { return clientGateway{} }
func (g *clientLogGlue) Listeners() []glue.Listener { return nil }

func newClientLogListener(t *testing.T) (*listener, func() string) {
	p := filepath.Join(t.TempDir(), "gateway.log")
	logBE, err := log.New(p, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logBE.Close() })
	cg := newCapGlue(t)
	cg.logBE = logBE
	cg.cfg.Debug.DisableRateLimit = true
	cg.cfg.Debug.ReauthInterval = 60000
	l := &listener{
		glue:       &clientLogGlue{capGlue: cg},
		log:        logBE.GetLogger("listener"),
		conns:      list.New(),
		connsByID:  make(map[[constants.RecipientIDLength]byte]*incomingConn),
		closeAllCh: make(chan interface{}),
	}
	return l, func() string {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		return string(b)
	}
}

func TestGatewayDoesNotLogClientIdentity(t *testing.T) {
	l, out := newClientLogListener(t)
	serverConn, clientConn := net.Pipe()
	c := newIncomingConn(l, serverConn, benchGeometry, benchKEMScheme, benchSignScheme)
	c.e = l.conns.PushFront(c)
	l.closeAllWg.Add(1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.worker()
	}()

	_, clientLink, err := benchKEMScheme.GenerateKeyPair()
	require.NoError(t, err)
	ad := make([]byte, constants.RecipientIDLength)
	_, err = rand.Reader.Read(ad)
	require.NoError(t, err)
	s, err := wire.NewSession(&wire.SessionConfig{
		KEMScheme:         benchKEMScheme,
		Geometry:          benchGeometry,
		Authenticator:     acceptAll{},
		AdditionalData:    ad,
		AuthenticationKey: clientLink,
		RandomReader:      rand.Reader,
	}, true)
	require.NoError(t, err)
	require.NoError(t, s.Initialize(context.Background(), clientConn))
	require.Eventually(t, func() bool {
		l.RLock()
		defer l.RUnlock()
		return l.connsByID[[constants.RecipientIDLength]byte(ad)] != nil
	}, 5*time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	s.Close()
	clientConn.Close()
	<-done

	logged := out()
	require.NotContains(t, logged, hex.EncodeToString(ad))
	blob, err := clientLink.Public().MarshalBinary()
	require.NoError(t, err)
	linkHash := hash.Sum256(blob)
	require.NotContains(t, logged, hex.EncodeToString(linkHash[:]))
}

func TestGatewayDoesNotLogClientRateLimitState(t *testing.T) {
	l, out := newClientLogListener(t)
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	c := newIncomingConn(l, serverConn, benchGeometry, benchKEMScheme, benchSignScheme)
	c.fromClient = true
	c.sendTokenIncr = time.Hour
	c.maxSendTokens = 1
	require.NoError(t, c.onSendPacket(&commands.SendPacket{SphinxPacket: make([]byte, benchGeometry.PacketLength)}))
	require.NotContains(t, out(), "Rate limit:")
}
