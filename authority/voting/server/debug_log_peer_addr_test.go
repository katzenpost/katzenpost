// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
)

func TestDebugLogOmitsPeerAddress(t *testing.T) {
	h := newPerPeerHarness(t, 8, false)
	p := filepath.Join(t.TempDir(), "debug.log")
	lb, err := log.New(p, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
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

	bad, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	badAddr := bad.LocalAddr().String()
	_, err = bad.Write(make([]byte, 64))
	require.NoError(t, err)
	require.NoError(t, bad.Close())
	waitForLog(t, p, "Failed session handshake")

	good, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { good.Close() })
	goodAddr := good.LocalAddr().String()
	s, err := wire.NewPKISession(&wire.SessionConfig{
		KEMScheme:          h.kemScheme,
		PKISignatureScheme: h.idScheme,
		Authenticator:      acceptAuthenticator{},
		AdditionalData:     h.cliHash[:],
		AuthenticationKey:  h.cliLinkPriv,
		RandomReader:       rand.Reader,
	}, true)
	require.NoError(t, err)
	require.NoError(t, s.Initialize(context.Background(), good))
	_, err = roundTrip(context.Background(), s)
	require.NoError(t, err)

	out := waitForLog(t, p, "Sent response")
	require.NotContains(t, out, badAddr)
	require.NotContains(t, out, goodAddr)
}
