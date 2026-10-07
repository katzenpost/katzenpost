// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package server

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/instrument"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func peerSendAttempts(t *testing.T, peer, result string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != "katzenpost_dirauth_peer_send_attempt_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["peer"] == peer && labels["result"] == result {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func TestSendToPeerPastDeadlineIsNotAttempted(t *testing.T) {
	sender := retryTestSender(t)
	instrument.StartPrometheusListener("", sender.log)
	var dials int32
	sender.dialContextFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		return nil, errors.New("connection refused")
	}
	peer := retryTestPeer()
	peer.Identifier = "responder-not-attempted"
	instrument.PeerConnected(peer.Identifier, true)
	_, err := sender.sendCommandToPeerWithDeadline(peer, retryTestCert(sender), time.Now().Add(-time.Second))
	require.Error(t, err)
	require.Zero(t, atomic.LoadInt32(&dials))
	require.Equal(t, 1.0, peerConnectedGauge(t, peer.Identifier))
	require.Equal(t, 1.0, peerSendAttempts(t, peer.Identifier, "not_attempted"))
	require.Zero(t, peerSendAttempts(t, peer.Identifier, "deadline_exceeded"))
}

func TestSendToPeerCountsTooEarlyApart(t *testing.T) {
	sender := retryTestSender(t)
	instrument.StartPrometheusListener("", sender.log)
	_, peer := certResponder(t, sender, func(n int32) uint8 {
		if n <= 2 {
			return commands.CertTooEarly
		}
		return commands.CertOk
	})
	peer.Identifier = "responder-too-early-count"
	resp, err := sender.sendCommandToPeerWithDeadline(peer, retryTestCert(sender), time.Now().Add(10*time.Second))
	require.NoError(t, err)
	require.Equal(t, uint8(commands.CertOk), resp.(*commands.CertStatus).ErrorCode)
	require.Equal(t, 2.0, peerSendAttempts(t, peer.Identifier, "too_early"))
	require.Zero(t, peerSendAttempts(t, peer.Identifier, "transient_error"))
	require.Equal(t, 1.0, peerSendAttempts(t, peer.Identifier, "ok"))
}
