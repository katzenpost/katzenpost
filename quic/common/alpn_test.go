// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"crypto/tls"
	"net/url"
	"testing"
	"time"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"
)

func handshakeWith(t *testing.T, listenOpts, dialOpts *Options) (tls.ConnectionState, error) {
	t.Helper()
	_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
	require.NoError(t, err)
	l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, newTestEpochKeys(t, t.TempDir(), newEpochClock(CurrentEpoch())), listenOpts)
	require.NoError(t, err)
	defer l.Close()
	u, err := url.Parse("quic://" + l.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialURL(u, ctx, nil, nil, dialOpts)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	return conn.(*QuicConn).Conn.ConnectionState().TLS, nil
}

func TestALPN(t *testing.T) {
	state, err := handshakeWith(t, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "pqnoise", state.NegotiatedProtocol)

	h3 := &Options{ALPN: "h3"}
	state, err = handshakeWith(t, h3, h3)
	require.NoError(t, err)
	require.Equal(t, "h3", state.NegotiatedProtocol)

	_, err = handshakeWith(t, nil, h3)
	require.Error(t, err, "a dial with another ALPN than the listener's must fail")
}
