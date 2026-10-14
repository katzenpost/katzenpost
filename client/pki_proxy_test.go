// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func pkiClientDialsQUIC(t *testing.T, upstream *config.UpstreamProxy, transports []string) bool {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { udp.Close() })
	cfg, err := config.LoadFile(testClientTOML)
	require.NoError(t, err)
	setupClientCallbacks(cfg)
	cfg.UpstreamProxy = upstream
	cfg.PreferedTransports = transports
	peer := cfg.VotingAuthority.Peers[0]
	peer.Addresses = []string{"quic://" + udp.LocalAddr().String()}
	peer.QUICKeyHash = bytes.Repeat([]byte{2}, cpki.QUICKeyHashSize)
	cfg.VotingAuthority.Peers = cfg.VotingAuthority.Peers[:1]

	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	c, err := New(cfg, logBackend)
	require.NoError(t, err)
	require.NoError(t, c.Start())
	defer c.Shutdown()

	epoch, _, _ := epochtime.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err = c.PKIClient.(cpki.Fetcher).GetPKIDocumentForEpoch(ctx, epoch)
	require.Error(t, err)
	return receivesUDP(udp, 500*time.Millisecond)
}

var optedInToQUIC = []string{cpki.TransportQUIC, cpki.TransportTCP}

func TestPKIClientNeverDialsQUICBehindAnUpstreamProxy(t *testing.T) {
	proxy := &config.UpstreamProxy{Type: "tor+socks5", Network: "tcp", Address: "127.0.0.1:1"}
	require.False(t, pkiClientDialsQUIC(t, proxy, optedInToQUIC), "the PKI client dialed an authority over quic around the upstream proxy")
}

func TestDefaultPKIClientNeverDialsQUIC(t *testing.T) {
	require.False(t, pkiClientDialsQUIC(t, &config.UpstreamProxy{}, nil), "a client that did not opt in to quic dialed an authority over quic")
	require.False(t, pkiClientDialsQUIC(t, &config.UpstreamProxy{}, []string{cpki.TransportTCP}), "a client that did not opt in to quic dialed an authority over quic")
}

func TestOptedInPKIClientDialsPinnedQUIC(t *testing.T) {
	require.True(t, pkiClientDialsQUIC(t, &config.UpstreamProxy{}, optedInToQUIC), "a client that opted in to quic did not dial its pinned authority over quic")
}
