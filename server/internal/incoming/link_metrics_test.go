// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package incoming

import (
	"context"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/quic/common"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
)

var linkMetricsOnce sync.Once

func incomingSample(name, transport string, labels ...string) float64 {
	linkMetricsOnce.Do(func() {
		defer func() { recover() }()
		instrument.StartPrometheusListener(&capGlue{cfg: &config.Config{Server: &config.Server{}}})
	})
	m := map[string]string{"transport": transport, "direction": "incoming"}
	for i := 0; i+1 < len(labels); i += 2 {
		m[labels[i]] = labels[i+1]
	}
	return instrument.LinkSample(name, m)
}

func tcpConnPair(t *testing.T) (net.Conn, net.Conn) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	client, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	server, err := l.Accept()
	require.NoError(t, err)
	return server, client
}

func quicConnPair(t *testing.T) (net.Conn, net.Conn) {
	_, identityPrivateKey, err := signSchemes.ByName("Ed25519 Sphincs+").GenerateKey()
	require.NoError(t, err)
	keys, err := common.NewEpochKeys(t.TempDir(), common.CurrentEpoch)
	require.NoError(t, err)
	l, err := common.ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, keys, nil)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	u, err := url.Parse("quic://" + l.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := common.DialURL(u, ctx, nil, nil, nil)
	require.NoError(t, err)
	server, err := l.Accept()
	require.NoError(t, err)
	return server, client
}

func serveIncomingLink(t *testing.T, server, client net.Conn, handshake bool, until func() bool) {
	l, _ := newClientLogListener(t)
	c := newIncomingConn(l, server, benchGeometry, benchKEMScheme, benchSignScheme)
	c.e = l.conns.PushFront(c)
	l.closeAllWg.Add(1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.worker()
	}()
	if handshake {
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
		defer s.Close()
		require.NoError(t, s.Initialize(context.Background(), client))
	} else {
		client.Write([]byte{0})
		client.Close()
	}
	require.Eventually(t, until, 10*time.Second, 10*time.Millisecond)
	client.Close()
	<-done
}

func TestIncomingLinksCountByTransport(t *testing.T) {
	for _, tc := range []struct {
		transport string
		pair      func(*testing.T) (net.Conn, net.Conn)
		other     string
	}{
		{"tcp", tcpConnPair, "quic"},
		{"quic", quicConnPair, "tcp"},
	} {
		t.Run(tc.transport, func(t *testing.T) {
			links := func() float64 { return incomingSample("katzenpost_links_established_total", tc.transport) }
			setups := func() float64 { return incomingSample("katzenpost_link_handshake_duration_seconds", tc.transport) }
			other := incomingSample("katzenpost_links_established_total", tc.other)
			beforeLinks, beforeSetups := links(), setups()
			server, client := tc.pair(t)
			serveIncomingLink(t, server, client, true, func() bool { return links() > beforeLinks })
			require.Equal(t, beforeLinks+1, links())
			require.Equal(t, beforeSetups+1, setups())
			require.Equal(t, other, incomingSample("katzenpost_links_established_total", tc.other))
		})
	}
}

func TestIncomingHandshakeFailuresCountByTransport(t *testing.T) {
	for _, tc := range []struct {
		transport string
		pair      func(*testing.T) (net.Conn, net.Conn)
	}{
		{"tcp", tcpConnPair},
		{"quic", quicConnPair},
	} {
		t.Run(tc.transport, func(t *testing.T) {
			failures := func() float64 {
				return incomingSample("katzenpost_link_failures_total", tc.transport, "reason", "handshake")
			}
			links := incomingSample("katzenpost_links_established_total", tc.transport)
			before := failures()
			server, client := tc.pair(t)
			serveIncomingLink(t, server, client, false, func() bool { return failures() > before })
			require.Equal(t, before+1, failures())
			require.Equal(t, links, incomingSample("katzenpost_links_established_total", tc.transport))
		})
	}
}
