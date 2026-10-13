// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package instrument

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
)

type noMetricsAddressGlue struct{ glue.Glue }

func (noMetricsAddressGlue) Config() *config.Config {
	return &config.Config{Server: &config.Server{}}
}

func registerOnce() {
	defer func() { recover() }()
	StartPrometheusListener(noMetricsAddressGlue{})
}

func TestLinkMetricsCountByTransportAndDirection(t *testing.T) {
	registerOnce()
	handshakes := func(transport, direction string) float64 {
		return LinkSample("katzenpost_link_handshake_duration_seconds", map[string]string{"transport": transport, "direction": direction})
	}
	established := func(transport, direction string) float64 {
		return LinkSample("katzenpost_links_established_total", map[string]string{"transport": transport, "direction": direction})
	}
	quicOut, tcpOut, quicIn := handshakes("quic", "outgoing"), handshakes("tcp", "outgoing"), established("quic", "incoming")
	quicOutLinks, tcpInLinks := established("quic", "outgoing"), established("tcp", "incoming")

	LinkHandshake("quic", "outgoing", 30*time.Millisecond)
	LinkHandshake("quic", "outgoing", 2*time.Second)
	LinkEstablished("quic", "outgoing")
	LinkEstablished("tcp", "incoming")

	require.Equal(t, quicOut+2, handshakes("quic", "outgoing"))
	require.Equal(t, tcpOut, handshakes("tcp", "outgoing"))
	require.Equal(t, quicOutLinks+1, established("quic", "outgoing"))
	require.Equal(t, tcpInLinks+1, established("tcp", "incoming"))
	require.Equal(t, quicIn, established("quic", "incoming"))
}

func TestLinkFailuresCountByReason(t *testing.T) {
	registerOnce()
	failures := func(transport, direction, reason string) float64 {
		return LinkSample("katzenpost_link_failures_total", map[string]string{"transport": transport, "direction": direction, "reason": reason})
	}
	pin, dial, handshake := failures("quic", "outgoing", "pin_mismatch"), failures("tcp", "outgoing", "dial"), failures("quic", "incoming", "handshake")

	LinkFailure("quic", "outgoing", "pin_mismatch")
	LinkFailure("tcp", "outgoing", "dial")
	LinkFailure("tcp", "outgoing", "dial")

	require.Equal(t, pin+1, failures("quic", "outgoing", "pin_mismatch"))
	require.Equal(t, dial+2, failures("tcp", "outgoing", "dial"))
	require.Equal(t, handshake, failures("quic", "incoming", "handshake"))
}

func TestQUICDialsCountByResult(t *testing.T) {
	registerOnce()
	dials := func(result string) float64 {
		return LinkSample("katzenpost_quic_dials_total", map[string]string{"result": result})
	}
	pinned, unpinned, mismatch := dials("pinned"), dials("unpinned"), dials("mismatch")

	QUICDial("pinned")
	QUICDial("pinned")
	QUICDial("mismatch")

	require.Equal(t, pinned+2, dials("pinned"))
	require.Equal(t, unpinned, dials("unpinned"))
	require.Equal(t, mismatch+1, dials("mismatch"))
}

func TestLinkSampleNeedsEveryLabel(t *testing.T) {
	registerOnce()
	LinkEstablished("tcp", "outgoing")
	require.Zero(t, LinkSample("katzenpost_links_established_total", map[string]string{"transport": "tcp", "direction": "sideways"}))
	require.Zero(t, LinkSample("katzenpost_no_such_metric", nil))
	require.NotZero(t, LinkSample("katzenpost_links_established_total", map[string]string{"transport": "tcp"}))
}
