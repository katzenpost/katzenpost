// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/rand"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/quic/common"
)

func TestQuicResponderReturnsOnceItsResponseIsSent(t *testing.T) {
	h := newPerPeerHarness(t, 8, false)
	ql, err := quic.ListenAddr("127.0.0.1:0", common.GenerateTLSConfig(), common.Config())
	require.NoError(t, err)
	l := &common.QuicListener{Listener: ql}
	t.Cleanup(func() { l.Close() })
	returned := make(chan time.Time, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		h.srv.state.Go(func() {
			h.srv.handleConn(c)
			returned <- time.Now()
		})
	}()

	u, err := url.Parse("quic://" + l.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := common.DialURL(u, ctx, nil, nil)
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
	require.NoError(t, s.Initialize(ctx, c))
	resp, err := roundTrip(ctx, s)
	require.NoError(t, err)
	received := time.Now()
	_, ok := resp.(*commands.Consensus)
	require.True(t, ok, "expected *Consensus, got %T", resp)

	select {
	case done := <-returned:
		require.Less(t, done.Sub(received), 50*time.Millisecond, "the responder held its connection slot %v after its response arrived", done.Sub(received))
	case <-time.After(5 * time.Second):
		t.Fatal("the responder did not return after its response")
	}
}
