// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
)

func TestOutboundHandshakeFailureLogOmitsAddressesAndKeys(t *testing.T) {
	h := newPerPeerHarness(t, 8, false)
	p := filepath.Join(t.TempDir(), "debug.log")
	lb, err := log.New(p, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
	st := h.srv.state
	st.log = lb.GetLogger("out")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write(make([]byte, 4096))
		time.Sleep(200 * time.Millisecond)
		c.Close()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	peerIDPub, _, err := h.idScheme.GenerateKey()
	require.NoError(t, err)
	peerLinkPub, _, err := h.kemScheme.GenerateKeyPair()
	require.NoError(t, err)
	peer := &config.Authority{
		Identifier:        "peer2",
		IdentityPublicKey: peerIDPub,
		LinkPublicKey:     config.LinkPublicKey{PublicKey: peerLinkPub},
	}
	session, err := st.newOutboundSession(conn, peer, 5*time.Second, 5*time.Second)
	require.NoError(t, err)
	require.Error(t, st.handshakeOutboundSession(session, conn, peer, 5*time.Second))

	selfHash := hash.Sum256From(h.srv.identityPublicKey)
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	out := string(b)
	require.Contains(t, out, "peer2")
	require.NotContains(t, out, ln.Addr().String())
	require.NotContains(t, out, conn.LocalAddr().String())
	require.NotContains(t, out, "PUBLIC KEY")
	require.NotContains(t, out, hex.EncodeToString(selfHash[:]))
}
