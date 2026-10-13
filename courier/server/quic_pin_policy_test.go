// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/courier/server/config"
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
	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	impostor, err := quic.ListenAddr("127.0.0.1:0", common.GenerateTLSConfig(), common.Config())
	require.NoError(t, err)
	t.Cleanup(func() { impostor.Close() })
	var dialed atomic.Int32
	dialer := &net.Dialer{Timeout: 5 * time.Second, ControlContext: func(context.Context, string, string, syscall.RawConn) error {
		dialed.Add(1)
		return errors.New("tcp dial")
	}}
	c := &outgoingConn{
		log: backendLog.GetLogger("test"),
		cfg: &config.Config{},
		dst: &cpki.ReplicaDescriptor{
			Name:        "storagereplica1",
			IdentityKey: []byte("identity"),
			Addresses: map[string][]string{
				cpki.TransportQUIC:  {"quic://" + impostor.Addr().String()},
				cpki.TransportOnion: {"onion://127.0.0.1:9"},
			},
			QUICKeyHash: bytes.Repeat([]byte{2}, 3*cpki.QUICKeyHashSize),
		},
	}
	before := pinMismatchDialFailures(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for range 2 {
		c.attemptConnections(&workerContext{ctx, cancel}, dialer, c.collectDestinationAddresses(), time.Millisecond, time.Millisecond)
	}
	require.Equal(t, int32(2), dialed.Load(), "a pin mismatch on quic did not fall back to the replica's other address")
	require.Equal(t, before+1, pinMismatchDialFailures(t), "a replica that failed its pin this epoch was dialed over quic again")
}
