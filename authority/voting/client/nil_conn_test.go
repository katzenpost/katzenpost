// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
)

// In initSession the loop variable shadows the outer err via
// u, err := url.Parse(addr). If the last usable address fails to parse, the
// url.Parse branch does a bare continue, so the loop falls through with conn
// still nil and no dial attempted; the following conn.SetDeadline then
// nil-dereferences and panics the calling goroutine, and FilterUsableAddresses
// does not drop unparseable addresses, so this is reachable.
//
// This test gives the peer a single unparseable address and asserts initSession
// returns a clean error instead of panicking.
func TestInitSessionNilConnReturnsError(t *testing.T) {
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	kemScheme := schemes.ByName("x25519")
	require.NotNil(t, kemScheme)
	_, linkPriv, err := kemScheme.GenerateKeyPair()
	require.NoError(t, err)

	p := &connector{
		cfg: &Config{
			LogBackend: logBackend,
		},
		log: logBackend.GetLogger("nil_conn_test"),
	}

	peer := &config.Authority{
		Identifier:    "test-authority",
		Addresses:     []string{"://x"},
		WireKEMScheme: "x25519",
	}

	require.NotPanics(t, func() {
		conn, serr := p.initSession(context.Background(), linkPriv, nil, peer)
		require.Error(t, serr)
		require.Nil(t, conn)
	}, "initSession must not panic when no address could be dialed")
}
