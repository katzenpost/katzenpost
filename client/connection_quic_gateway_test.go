// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike/schemes"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	vServerConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/transport"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func newQUICGatewayConnection(t *testing.T, upstream *config.UpstreamProxy) (*connection, *net.UDPConn) {
	conn, udp := newGatewayTestConnection(t, upstream)
	startConnect(t, conn)
	return conn, udp
}

func newGatewayTestConnection(t *testing.T, upstream *config.UpstreamProxy) (*connection, *net.UDPConn) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { udp.Close() })

	pkiScheme := signSchemes.ByName("ed25519")
	authIdPubKey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)
	authLinkPubKey, _, err := kemSchemes.ByName("x25519").GenerateKeyPair()
	require.NoError(t, err)

	cfg := &config.Config{
		Listen: &transport.ListenConfig{
			Tcp: &transport.TcpListenConfig{Address: "127.0.0.1:0"},
		},
		PKISignatureScheme: "ed25519",
		WireKEMScheme:      "x25519",
		SphinxGeometry:     geo.GeometryFromUserForwardPayloadLength(schemes.ByName("x25519"), 2000, false, 5),
		Logging:            &config.Logging{Level: "ERROR"},
		UpstreamProxy:      upstream,
		Debug:              &config.Debug{},
		PinnedGateways:     &config.Gateways{},
		PreferedTransports: cpki.ClientTransports,
		VotingAuthority: &config.VotingAuthority{
			Peers: []*vServerConfig.Authority{
				{
					Identifier:         "auth",
					IdentityPublicKey:  authIdPubKey,
					PKISignatureScheme: "ed25519",
					LinkPublicKey:      vServerConfig.LinkPublicKey{PublicKey: authLinkPubKey},
					WireKEMScheme:      "x25519",
					Addresses:          []string{"tcp://127.0.0.1:1301"},
				},
			},
		},
	}
	setupClientCallbacks(cfg)

	logbackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	c, err := New(cfg, logbackend)
	require.NoError(t, err)

	prevAttempts, prevDelay := waitForCurrentDocumentAttempts, waitForCurrentDocumentRetryDelay
	waitForCurrentDocumentAttempts, waitForCurrentDocumentRetryDelay = 1, time.Millisecond
	t.Cleanup(func() {
		waitForCurrentDocumentAttempts, waitForCurrentDocumentRetryDelay = prevAttempts, prevDelay
	})

	conn := newConnection(c)
	c.pki = &pki{
		c:               c,
		log:             logbackend.GetLogger("pki"),
		failedFetches:   make(map[uint64]error),
		forceUpdateCh:   make(chan interface{}, 1),
		consensusGetter: conn,
	}
	conn.descriptor = &cpki.MixDescriptor{
		Name:          "gateway",
		IdentityKey:   []byte("identity"),
		LinkKey:       []byte("linkkey"),
		Addresses:     map[string][]string{cpki.TransportQUIC: {"quic://" + udp.LocalAddr().String()}},
		IsGatewayNode: true,
		QUICKeyHash:   bytes.Repeat([]byte{2}, cpki.QUICKeyHashSize),
	}
	conn.pkiEpoch = 42
	return conn, udp
}

func startConnect(t *testing.T, conn *connection) {
	done := make(chan struct{})
	go func() {
		conn.doConnect(context.Background())
		close(done)
	}()
	t.Cleanup(func() {
		conn.Halt()
		<-done
	})
}

func receivesUDP(udp *net.UDPConn, wait time.Duration) bool {
	_ = udp.SetReadDeadline(time.Now().Add(wait))
	_, _, err := udp.ReadFromUDP(make([]byte, 2048))
	return err == nil
}

func TestConnectWithProxyNeverDialsQUIC(t *testing.T) {
	_, udp := newQUICGatewayConnection(t, &config.UpstreamProxy{Type: "tor+socks5", Network: "tcp", Address: "127.0.0.1:1"})
	require.False(t, receivesUDP(udp, 2*time.Second))
}

func TestConnectWithoutProxyDialsQUIC(t *testing.T) {
	_, udp := newQUICGatewayConnection(t, &config.UpstreamProxy{})
	require.True(t, receivesUDP(udp, 5*time.Second))
}

func TestDefaultClientNeverDialsQUICToItsGateway(t *testing.T) {
	conn, udp := newGatewayTestConnection(t, &config.UpstreamProxy{})
	conn.client.cfg.PreferedTransports = nil
	startConnect(t, conn)
	require.False(t, receivesUDP(udp, 2*time.Second), "a client that did not opt in to quic dialed its gateway over quic")
}

func TestConnectNeverDialsAnUnpinnedQUICGateway(t *testing.T) {
	conn, udp := newGatewayTestConnection(t, &config.UpstreamProxy{})
	conn.descriptor.QUICKeyHash = nil
	startConnect(t, conn)
	require.False(t, receivesUDP(udp, 2*time.Second), "a gateway that published no QUIC key hash was dialed over unpinned quic")
}
