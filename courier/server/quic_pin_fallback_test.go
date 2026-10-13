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

func TestPinMismatchDoesNotFallBackToAnUnpinnedAddress(t *testing.T) {
	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	impostor, err := quic.ListenAddr("127.0.0.1:0", common.GenerateTLSConfig(), common.Config())
	require.NoError(t, err)
	t.Cleanup(func() { impostor.Close() })
	var dialed atomic.Int32
	dialer := &net.Dialer{Timeout: 5 * time.Second, ControlContext: func(context.Context, string, string, syscall.RawConn) error {
		dialed.Add(1)
		return errors.New("unpinned dial")
	}}
	c := &outgoingConn{
		log: backendLog.GetLogger("test"),
		cfg: &config.Config{},
		dst: &cpki.ReplicaDescriptor{
			Name: "storagereplica1",
			Addresses: map[string][]string{
				cpki.TransportQUIC:  {"quic://" + impostor.Addr().String()},
				cpki.TransportOnion: {"onion://127.0.0.1:9"},
			},
			QUICKeyHash: bytes.Repeat([]byte{2}, 3*cpki.QUICKeyHashSize),
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c.attemptConnections(&workerContext{ctx, cancel}, dialer, c.collectDestinationAddresses(), time.Millisecond, time.Millisecond)
	require.Zero(t, dialed.Load(), "a pin mismatch on quic fell back to an unpinned dial of the same replica")
}
