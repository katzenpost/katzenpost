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

func TestPKIClientNeverDialsQUICBehindAnUpstreamProxy(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { udp.Close() })
	cfg, err := config.LoadFile(testClientTOML)
	require.NoError(t, err)
	setupClientCallbacks(cfg)
	cfg.UpstreamProxy = &config.UpstreamProxy{Type: "tor+socks5", Network: "tcp", Address: "127.0.0.1:1"}
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
	require.False(t, receivesUDP(udp, 500*time.Millisecond), "the PKI client dialed an authority over quic around the upstream proxy")
}
