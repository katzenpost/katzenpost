// SPDX-License-Identifier: AGPL-3.0-only

package outgoing

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

type boundaryPKI struct {
	glue.PKI
	crossed atomic.Bool
	auths   atomic.Int32
}

func (p *boundaryPKI) AuthenticateConnection(*wire.PeerCredentials, bool) (*cpki.MixDescriptor, bool, bool) {
	p.auths.Add(1)
	return nil, p.crossed.Load(), true
}

func (p *boundaryPKI) OutgoingDestinations() map[[sConstants.NodeIDLength]byte]*cpki.MixDescriptor {
	return map[[sConstants.NodeIDLength]byte]*cpki.MixDescriptor{}
}

func (p *boundaryPKI) CurrentDocument() (*cpki.Document, error) {
	return nil, errors.New("no document")
}

type boundaryGlue struct {
	glue.Glue
	cfg     *config.Config
	backend *log.Backend
	idPub   sign.PublicKey
	link    kem.PrivateKey
	pki     *boundaryPKI
}

func (g *boundaryGlue) Config() *config.Config            { return g.cfg }
func (g *boundaryGlue) LogBackend() *log.Backend          { return g.backend }
func (g *boundaryGlue) IdentityPublicKey() sign.PublicKey { return g.idPub }
func (g *boundaryGlue) LinkKey() kem.PrivateKey           { return g.link }
func (g *boundaryGlue) PKI() glue.PKI                     { return g.pki }

func servePackets(t *testing.T, ln net.Listener, idPub sign.PublicKey, link kem.PrivateKey, got chan<- struct{}) {
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	id := hash.Sum256From(idPub)
	s, err := wire.NewSession(&wire.SessionConfig{
		KEMScheme:         benchKEMScheme,
		Geometry:          benchGeometry,
		Authenticator:     &acceptAllAuthenticator{},
		AdditionalData:    id[:],
		AuthenticationKey: link,
		RandomReader:      rand.Reader,
	}, false)
	if err != nil {
		return
	}
	defer s.Close()
	if s.Initialize(context.Background(), c) != nil {
		return
	}
	for {
		cmd, err := s.RecvCommand(context.Background())
		if err != nil {
			return
		}
		if _, ok := cmd.(*commands.SendPacket); ok {
			got <- struct{}{}
		}
	}
}

func TestEpochChangeLetsAnEarlyConnectedLinkSend(t *testing.T) {
	scheme := signSchemes.ByName(testSchemeName)
	idPub, _, err := scheme.GenerateKey()
	require.NoError(t, err)
	_, link, err := benchKEMScheme.GenerateKeyPair()
	require.NoError(t, err)
	peerID, _, err := scheme.GenerateKey()
	require.NoError(t, err)
	peerLinkPub, peerLink, err := benchKEMScheme.GenerateKeyPair()
	require.NoError(t, err)
	peerIDBlob, err := peerID.MarshalBinary()
	require.NoError(t, err)
	peerLinkBlob, err := peerLinkPub.MarshalBinary()
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	got := make(chan struct{}, 4)
	go servePackets(t, ln, peerID, peerLink, got)

	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	p := &boundaryPKI{}
	g := &boundaryGlue{
		cfg:     &config.Config{Debug: &config.Debug{HandshakeTimeout: 5000, ReauthInterval: int(time.Hour / time.Millisecond), SendSlack: int(time.Hour / time.Millisecond)}},
		backend: backend,
		idPub:   idPub,
		link:    link,
		pki:     p,
	}
	co := &connector{
		glue:          g,
		log:           backend.GetLogger("connector"),
		conns:         make(map[[sConstants.NodeIDLength]byte]*outgoingConn),
		forceUpdateCh: make(chan interface{}, 1),
		closeAllCh:    make(chan interface{}),
	}
	co.Go(co.worker)
	defer co.Halt()

	c := newOutgoingConn(co, &cpki.MixDescriptor{Name: "peer", IdentityKey: peerIDBlob, LinkKey: peerLinkBlob}, benchGeometry, benchKEMScheme)
	co.Lock()
	co.conns[hash.Sum256(peerIDBlob)] = c
	co.Unlock()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	closeCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		c.onConnEstablished(conn, closeCh)
		close(done)
	}()
	defer func() {
		close(closeCh)
		<-done
	}()
	require.Eventually(t, func() bool { return p.auths.Load() >= 1 }, 10*time.Second, 10*time.Millisecond)

	p.crossed.Store(true)
	co.ForceUpdate()
	require.Eventually(t, func() bool { return len(co.forceUpdateCh) == 0 }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(200 * time.Millisecond)

	pkt, err := packet.New(make([]byte, benchGeometry.PacketLength), benchGeometry)
	require.NoError(t, err)
	pkt.DispatchAt = time.Now()
	c.dispatchPacket(pkt)

	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("packet dropped after the epoch change: the link still holds the canSend decided at handshake")
	}
}
