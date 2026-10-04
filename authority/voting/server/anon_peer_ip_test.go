// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
)

func noticeLogTCP(t *testing.T, h *perPeerHarness) (string, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "notice.log")
	lb, err := log.New(p, "NOTICE", false)
	require.NoError(t, err)
	h.srv.logBackend = lb
	h.srv.log = lb.GetLogger("resp")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			h.srv.state.Go(func() { h.srv.handleConn(c) })
		}
	}()
	return p, ln.Addr().String()
}

func waitForLog(t *testing.T, p, want string) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), want) {
			return string(b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("log never contained %q", want)
	return ""
}

func TestNoticeLogOmitsAnonymousPeerIPOnHandshakeFailure(t *testing.T) {
	h := newPerPeerHarness(t, 8, false)
	p, addr := noticeLogTCP(t, h)

	c, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	_, err = c.Write(make([]byte, 64))
	require.NoError(t, err)
	require.NoError(t, c.Close())

	out := waitForLog(t, p, "Failed session handshake")
	require.NotContains(t, out, "127.0.0.1")
}

func TestNoticeLogOmitsUnnamedPeerIPAtPerPeerCap(t *testing.T) {
	h := newPerPeerHarness(t, 1, true)
	p, addr := noticeLogTCP(t, h)

	dial := func() {
		c, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		t.Cleanup(func() { c.Close() })
		s, err := wire.NewPKISession(&wire.SessionConfig{
			KEMScheme:          h.kemScheme,
			PKISignatureScheme: h.idScheme,
			Authenticator:      acceptAuthenticator{},
			AdditionalData:     h.cliHash[:],
			AuthenticationKey:  h.cliLinkPriv,
			RandomReader:       rand.Reader,
		}, true)
		require.NoError(t, err)
		require.NoError(t, s.Initialize(context.Background(), c))
		_, _ = roundTrip(context.Background(), s)
	}
	dial()
	dial()

	out := waitForLog(t, p, "per-peer connection cap reached")
	require.NotContains(t, out, "127.0.0.1")
}
