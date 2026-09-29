// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
)

// initSession dials the peer successfully, then if the peer's configured
// WireKEMScheme or PKISignatureScheme name is unregistered, used to return an
// error without closing the connection it had just dialed. Every call leaked
// one socket. These tests give a peer with an unregistered scheme name over a
// net.Pipe standing in for the dial, and assert the connector's side of the
// pipe is actually closed once initSession returns its error.
func TestInitSessionClosesConnOnUnknownKEMScheme(t *testing.T) {
	testInitSessionClosesConnOnSchemeError(t, &config.Authority{
		Identifier:    "test-authority",
		Addresses:     []string{"tcp://127.0.0.1:1234"},
		WireKEMScheme: "no-such-kem-scheme",
	})
}

func TestInitSessionClosesConnOnUnknownPKISignatureScheme(t *testing.T) {
	testInitSessionClosesConnOnSchemeError(t, &config.Authority{
		Identifier:         "test-authority",
		Addresses:          []string{"tcp://127.0.0.1:1234"},
		WireKEMScheme:      "x25519",
		PKISignatureScheme: "no-such-sig-scheme",
	})
}

func testInitSessionClosesConnOnSchemeError(t *testing.T, peer *config.Authority) {
	t.Helper()
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	kemScheme := schemes.ByName("x25519")
	require.NotNil(t, kemScheme)
	_, linkPriv, err := kemScheme.GenerateKeyPair()
	require.NoError(t, err)

	connectorSide, peerSide := net.Pipe()
	t.Cleanup(func() { _ = peerSide.Close() })

	p := &connector{
		cfg: &Config{
			LogBackend: logBackend,
			DialContextFn: func(ctx context.Context, network, address string) (net.Conn, error) {
				return connectorSide, nil
			},
		},
		log: logBackend.GetLogger("scheme_lookup_conn_leak_test"),
	}

	conn, serr := p.initSession(context.Background(), linkPriv, nil, peer)
	require.Error(t, serr)
	require.Nil(t, conn)

	// A closed net.Pipe end makes the peer's Read return; a leaked connection
	// would leave this blocked until the test's own timeout.
	done := make(chan struct{})
	go func() {
		_, _ = peerSide.Read(make([]byte, 1))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("initSession did not close the connection on a scheme lookup error")
	}
}
