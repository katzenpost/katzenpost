// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/quic/common"
)

func pinMismatchDialFailures(t *testing.T) float64 {
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != "katzenpost_outgoing_dial_failures_total" {
			continue
		}
		for _, m := range family.GetMetric() {
			for _, label := range m.GetLabel() {
				if label.GetName() == "reason" && label.GetValue() == "pin_mismatch" {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestPinMismatchFallsBackToTCPForTheEpoch(t *testing.T) {
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	schemes := NewTestSchemes()
	geometry := CreateTestGeometryCustom(schemes, 1234, 5)
	keys := GenerateTestKeys(t, schemes)
	cfg := CreateTestConfig(t, schemes, geometry, CreateTestTempDir(t, "replica_pin_policy_test"), "replica1", []string{"tcp://127.0.0.1:1"})
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
		return errors.New("tcp dial")
	}}

	dst := GenerateTestReplica(t, schemes, 0)
	dst.Addresses = map[string][]string{
		pki.TransportQUIC:  {"quic://" + impostor.Addr().String()},
		pki.TransportOnion: {"onion://127.0.0.1:9"},
	}
	dst.QUICKeyHash = bytes.Repeat([]byte{2}, 3*pki.QUICKeyHashSize)
	c := newOutgoingConn(s.connector, dst, geometry, schemes.Link)

	before := pinMismatchDialFailures(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for range 2 {
		c.attemptConnectionToAddresses(c.getDestinationAddresses(), ctx, dialer, time.Millisecond, time.Millisecond)
	}
	require.Equal(t, int32(2), dialed.Load(), "a pin mismatch on quic did not fall back to the replica's other address")
	require.Equal(t, before+1, pinMismatchDialFailures(t), "a replica that failed its pin this epoch was dialed over quic again")
}
