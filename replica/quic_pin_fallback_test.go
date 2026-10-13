// SPDX-License-Identifier: AGPL-3.0-only

package replica

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
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/quic/common"
)

func TestPinMismatchDoesNotFallBackToAnUnpinnedAddress(t *testing.T) {
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	schemes := NewTestSchemes()
	geometry := CreateTestGeometryCustom(schemes, 1234, 5)
	keys := GenerateTestKeys(t, schemes)
	cfg := CreateTestConfig(t, schemes, geometry, CreateTestTempDir(t, "replica_pin_test"), "replica1", []string{"tcp://127.0.0.1:1"})
	cfg.SetDefaultTimeouts()
	s := &Server{
		identityPublicKey: keys.IdentityPubKey,
		linkKey:           keys.LinkPrivKey,
		cfg:               cfg,
		logBackend:        logBackend,
	}
	s.connector = newMockConnector(s)

	impostor, err := quic.ListenAddr("127.0.0.1:0", common.GenerateTLSConfig(), common.Config())
	require.NoError(t, err)
	t.Cleanup(func() { impostor.Close() })
	var dialed atomic.Int32
	dialer := net.Dialer{Timeout: 5 * time.Second, ControlContext: func(context.Context, string, string, syscall.RawConn) error {
		dialed.Add(1)
		return errors.New("unpinned dial")
	}}

	dst := GenerateTestReplica(t, schemes, 0)
	dst.Addresses = map[string][]string{
		pki.TransportQUIC:  {"quic://" + impostor.Addr().String()},
		pki.TransportOnion: {"onion://127.0.0.1:9"},
	}
	dst.QUICKeyHash = bytes.Repeat([]byte{2}, 3*pki.QUICKeyHashSize)
	c := newOutgoingConn(s.connector, dst, geometry, schemes.Link)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c.attemptConnectionToAddresses(c.getDestinationAddresses(), ctx, dialer, time.Millisecond, time.Millisecond)
	require.Zero(t, dialed.Load(), "a pin mismatch on quic fell back to an unpinned dial of the same replica")
}
