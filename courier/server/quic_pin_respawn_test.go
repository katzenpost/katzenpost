// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/quic/common"
)

func TestStrictPinMismatchOutlivesTheConnWorker(t *testing.T) {
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	impostor, err := quic.ListenAddr("127.0.0.1:0", common.GenerateTLSConfig(), common.Config())
	require.NoError(t, err)
	t.Cleanup(func() { impostor.Close() })
	var dialed atomic.Int32
	dialer := &net.Dialer{Timeout: 5 * time.Second, ControlContext: func(context.Context, string, string, syscall.RawConn) error {
		dialed.Add(1)
		return errors.New("tcp dial")
	}}
	cfg := &config.Config{
		WireKEMScheme:       "x25519",
		PKIScheme:           "ed25519",
		EnvelopeScheme:      "x25519",
		DisableDecoyTraffic: true,
		QUIC:                &common.Options{PinMismatch: common.PinMismatchStrict},
	}
	co := &Connector{server: &Server{logBackend: backend}}
	dst := &cpki.ReplicaDescriptor{
		Name:        "storagereplica1",
		IdentityKey: []byte("identity"),
		Addresses:   map[string][]string{cpki.TransportQUIC: {"quic://" + impostor.Addr().String()}},
		QUICKeyHash: bytes.Repeat([]byte{2}, cpki.QUICKeyHashSize),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for range 2 {
		c := newOutgoingConn(co, dst, cfg, &Courier{})
		t.Cleanup(c.sender.Halt)
		c.attemptConnections(&workerContext{ctx, cancel}, dialer, c.collectDestinationAddresses(), time.Millisecond, time.Millisecond)
		dst.Addresses[cpki.TransportTCP] = []string{"tcp://127.0.0.1:9"}
	}
	require.Zero(t, dialed.Load(), "a respawned conn dialed tcp after a strict pin mismatch this epoch")
}
