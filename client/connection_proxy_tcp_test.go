// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func TestConnectWithProxyKeepsTCP(t *testing.T) {
	conn, udp := newGatewayTestConnection(t, &config.UpstreamProxy{Type: "tor+socks5", Network: "tcp", Address: "127.0.0.1:1"})

	var mu sync.Mutex
	var dialed []string
	got := make(chan struct{}, 1)
	conn.client.DialContextFn = func(_ context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, network+" "+addr)
		mu.Unlock()
		select {
		case got <- struct{}{}:
		default:
		}
		return nil, errors.New("proxy unreachable")
	}
	conn.descriptor = &cpki.MixDescriptor{
		Name:        "gateway",
		IdentityKey: []byte("identity"),
		LinkKey:     []byte("linkkey"),
		Addresses: map[string][]string{
			cpki.TransportQUIC: {"quic://" + udp.LocalAddr().String()},
			cpki.TransportTCP:  {"tcp://127.0.0.1:1302"},
		},
		IsGatewayNode: true,
	}
	startConnect(t, conn)

	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("proxied connect never dialed tcp")
	}
	require.False(t, receivesUDP(udp, time.Second))
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, "tcp 127.0.0.1:1302", dialed[0])
	for _, d := range dialed {
		require.Equal(t, "tcp 127.0.0.1:1302", d)
	}
}
