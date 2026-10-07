// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package server

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/instrument"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func peerConnectedGauge(t *testing.T, peer string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != "katzenpost_dirauth_peer_connected" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "peer" && l.GetValue() == peer {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	require.FailNow(t, "peer_connected gauge not found", peer)
	return 0
}

func TestSendToPeerTooEarlyExhaustionKeepsPeerConnected(t *testing.T) {
	sender := retryTestSender(t)
	instrument.StartPrometheusListener("", sender.log)
	_, peer := certResponder(t, sender, func(int32) uint8 { return commands.CertTooEarly })
	peer.Identifier = "responder-too-early-metric"
	instrument.PeerConnected(peer.Identifier, true)
	resp, err := sender.sendCommandToPeerWithDeadline(peer, retryTestCert(sender), time.Now().Add(300*time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, uint8(commands.CertTooEarly), resp.(*commands.CertStatus).ErrorCode)
	require.Equal(t, 1.0, peerConnectedGauge(t, peer.Identifier))
}
