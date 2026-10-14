// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/quic/common"
)

func TestConnectPinMismatchFallsBackToTCPForTheEpoch(t *testing.T) {
	conn, _ := newGatewayTestConnection(t, &config.UpstreamProxy{})
	impostor, err := quic.ListenAddr("127.0.0.1:0", common.GenerateTLSConfig(), common.Config())
	require.NoError(t, err)
	t.Cleanup(func() { impostor.Close() })
	var tcpDials, mismatches atomic.Int32
	saved := defaultDialer
	t.Cleanup(func() { defaultDialer = saved })
	defaultDialer.ControlContext = func(context.Context, string, string, syscall.RawConn) error {
		tcpDials.Add(1)
		return errors.New("tcp dial")
	}
	conn.client.cfg.Callbacks.OnConnFn = func(err error) {
		var connectErr *ConnectError
		if errors.As(err, &connectErr) && errors.Is(connectErr.Err, common.ErrQUICKeyMismatch) {
			mismatches.Add(1)
		}
	}
	require.NoError(t, conn.client.SetPreferredTransports([]string{cpki.TransportQUIC, cpki.TransportTCP}))
	conn.retryDelay = int64(-time.Hour)
	conn.descriptor = &cpki.MixDescriptor{
		Name:        "gateway",
		IdentityKey: []byte("identity"),
		LinkKey:     []byte("linkkey"),
		Addresses: map[string][]string{
			cpki.TransportQUIC: {"quic://" + impostor.Addr().String()},
			cpki.TransportTCP:  {"tcp://127.0.0.1:9"},
		},
		QUICKeyHash:   bytes.Repeat([]byte{2}, 3*cpki.QUICKeyHashSize),
		IsGatewayNode: true,
	}
	startConnect(t, conn)

	deadline := time.Now().Add(15 * time.Second)
	for tcpDials.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	require.GreaterOrEqual(t, tcpDials.Load(), int32(3), "a pin mismatch on quic did not fall back to the gateway's tcp address")
	require.Equal(t, int32(1), mismatches.Load(), "a gateway that failed its pin this epoch was dialed over quic again")
}
