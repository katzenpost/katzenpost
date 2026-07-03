// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
)

type writeFailConn struct {
	net.Conn
	fail *atomic.Bool
}

func (c writeFailConn) Write(b []byte) (int, error) {
	if c.fail.Load() {
		return 0, errors.New("write refused")
	}
	return c.Conn.Write(b)
}

func TestNoticeLogOmitsUnnamedPeerIPOnSendFailure(t *testing.T) {
	h := newPerPeerHarness(t, 8, false)
	p := filepath.Join(t.TempDir(), "notice.log")
	lb, err := log.New(p, "NOTICE", false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
	h.srv.logBackend = lb
	h.srv.log = lb.GetLogger("resp")

	var fail atomic.Bool
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		h.srv.state.Go(func() { h.srv.handleConn(writeFailConn{Conn: c, fail: &fail}) })
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
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
	fail.Store(true)
	_, _ = roundTrip(context.Background(), s)

	out := waitForLog(t, p, "Failed to send response")
	require.Contains(t, out, "Peer anonymous: Failed to send response")
	require.NotContains(t, out, "127.0.0.1")
}
