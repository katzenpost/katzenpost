// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

type retryCountingConn struct {
	net.PacketConn
	retries atomic.Int32
}

func (c *retryCountingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if n > 0 && b[0]&0xf0 == 0xf0 {
		c.retries.Add(1)
	}
	return n, addr, err
}

func retriesFor(t *testing.T, opts *Options) int32 {
	t.Helper()
	_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
	require.NoError(t, err)
	l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, newTestEpochKeys(t, t.TempDir(), newEpochClock(CurrentEpoch())), opts)
	require.NoError(t, err)
	defer l.Close()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	counting := &retryCountingConn{PacketConn: udp}
	tr := &quic.Transport{Conn: counting}
	defer tr.Close()
	defer udp.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := Config()
	cfg.Versions = []quic.Version{quic.Version1}
	conn, err := tr.Dial(ctx, l.Addr(), &tls.Config{InsecureSkipVerify: true, NextProtos: opts.nextProtos()}, cfg)
	require.NoError(t, err)
	conn.CloseWithError(0, "")
	return counting.retries.Load()
}

func TestAddressValidation(t *testing.T) {
	require.Positive(t, retriesFor(t, nil), "a new connection must be retried by default")
	require.Positive(t, retriesFor(t, &Options{AddressValidation: AddressValidationAlways}))
	require.Equal(t, int32(0), retriesFor(t, &Options{AddressValidation: AddressValidationUnderLoad}), "one handshake is no load")
	require.Equal(t, int32(0), retriesFor(t, &Options{AddressValidation: AddressValidationOff}))
}

func TestUnderLoadCountsHandshakesInFlight(t *testing.T) {
	h := &handshakes{}
	var cancels []context.CancelFunc
	defer func() {
		for _, cancel := range cancels {
			cancel()
		}
	}()
	open := func() context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		connCtx, err := h.connContext(ctx, nil)
		require.NoError(t, err)
		return connCtx
	}
	for range UnderLoadHandshakes - 1 {
		open()
	}
	require.False(t, h.underLoad(nil))
	last := open()
	require.True(t, h.underLoad(nil))
	settle := last.Value(handshakeSettleKey{}).(func())
	settle()
	settle()
	require.False(t, h.underLoad(nil))
	cancels[len(cancels)-1]()
	require.Equal(t, int64(UnderLoadHandshakes-1), h.inFlight.Load(), "a settled handshake was counted out twice")
	for _, cancel := range cancels {
		cancel()
	}
	require.Eventually(t, func() bool { return h.inFlight.Load() == 0 }, 5*time.Second, 10*time.Millisecond)
}
