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

	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
)

func TestInitSessionWithDialerKeepsTCP(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { udp.Close() })

	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	_, linkPriv, err := schemes.ByName("x25519").GenerateKeyPair()
	require.NoError(t, err)

	var mu sync.Mutex
	var dialed []string
	p := &connector{
		cfg: &Config{LogBackend: logBackend, DialContextFn: func(_ context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, network+" "+addr)
			mu.Unlock()
			return nil, errors.New("proxy unreachable")
		}},
		log: logBackend.GetLogger("tcp"),
	}
	peer := &config.Authority{
		Identifier:    "auth",
		Addresses:     []string{"quic://" + udp.LocalAddr().String(), "tcp://127.0.0.1:1303"},
		WireKEMScheme: "x25519",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = p.initSession(ctx, linkPriv, nil, peer)
	require.Error(t, err)
	require.False(t, receivesUDP(udp, time.Second))
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"tcp 127.0.0.1:1303"}, dialed)
}
