// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/quic/common"
)

func TestConnectPinMismatchDoesNotFallBackToAnUnpinnedAddress(t *testing.T) {
	conn, _ := newGatewayTestConnection(t, &config.UpstreamProxy{})
	conn.client.cfg.QUIC = &common.Options{PinMismatch: common.PinMismatchStrict}
	impostor, err := quic.ListenAddr("127.0.0.1:0", common.GenerateTLSConfig(), common.Config())
	require.NoError(t, err)
	t.Cleanup(func() { impostor.Close() })
	dialed := make(chan struct{}, 1)
	saved := defaultDialer
	t.Cleanup(func() { defaultDialer = saved })
	defaultDialer.ControlContext = func(context.Context, string, string, syscall.RawConn) error {
		select {
		case dialed <- struct{}{}:
		default:
		}
		return errors.New("unpinned dial")
	}
	conn.descriptor = &cpki.MixDescriptor{
		Name:        "gateway",
		IdentityKey: []byte("identity"),
		LinkKey:     []byte("linkkey"),
		Addresses: map[string][]string{
			cpki.TransportQUIC:  {"quic://" + impostor.Addr().String()},
			cpki.TransportOnion: {"onion://127.0.0.1:9"},
		},
		QUICKeyHash:   bytes.Repeat([]byte{2}, 3*cpki.QUICKeyHashSize),
		IsGatewayNode: true,
	}
	startConnect(t, conn)

	select {
	case <-dialed:
		t.Fatal("a pin mismatch on quic fell back to an unpinned dial of the gateway")
	case <-time.After(20 * time.Second):
	}
}
