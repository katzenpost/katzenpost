// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
)

func dialedHosts(t *testing.T, local, peerAddrs []string) []string {
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	_, linkPriv, err := schemes.ByName("x25519").GenerateKeyPair()
	require.NoError(t, err)

	var mu sync.Mutex
	var dialed []string
	p := &connector{
		cfg: &Config{
			LogBackend:     logBackend,
			LocalAddresses: local,
			DialContextFn: func(ctx context.Context, network, addr string) (net.Conn, error) {
				mu.Lock()
				defer mu.Unlock()
				dialed = append(dialed, addr)
				return nil, errors.New("refused")
			},
		},
		log: logBackend.GetLogger("ip6_filter_test"),
	}
	peer := &config.Authority{Identifier: "auth", Addresses: peerAddrs, WireKEMScheme: "x25519"}
	conn, err := p.initSession(context.Background(), linkPriv, nil, peer)
	require.Error(t, err)
	require.Nil(t, conn)
	mu.Lock()
	defer mu.Unlock()
	return dialed
}

func TestInitSessionSkipsUnroutableIPv6(t *testing.T) {
	got := dialedHosts(t, []string{"tcp://198.51.100.7:29483"}, []string{"tcp://[2001:db8::1]:29483", "tcp://192.0.2.1:29483"})
	require.Equal(t, []string{"192.0.2.1:29483"}, got)
}

func TestInitSessionDialsIPv6WhenNothingElse(t *testing.T) {
	got := dialedHosts(t, []string{"tcp://198.51.100.7:29483"}, []string{"tcp://[2001:db8::1]:29483"})
	require.Equal(t, []string{"[2001:db8::1]:29483"}, got)
}

func TestInitSessionUnfilteredWithoutLocalAddresses(t *testing.T) {
	got := dialedHosts(t, nil, []string{"tcp://[2001:db8::1]:29483", "tcp://192.0.2.1:29483"})
	require.ElementsMatch(t, []string{"[2001:db8::1]:29483", "192.0.2.1:29483"}, got)
}
