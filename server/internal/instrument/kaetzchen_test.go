// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package instrument

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func droppedResponses(t *testing.T) map[string]float64 {
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(kaetzchenResponsesDropped))
	families, err := reg.Gather()
	require.NoError(t, err)
	got := make(map[string]float64)
	for _, f := range families {
		require.Equal(t, "katzenpost_kaetzchen_dropped_responses_total", f.GetName())
		for _, m := range f.GetMetric() {
			require.Len(t, m.GetLabel(), 1)
			require.Equal(t, "capability", m.GetLabel()[0].GetName())
			got[m.GetLabel()[0].GetValue()] = m.GetCounter().GetValue()
		}
	}
	return got
}

func TestKaetzchenResponsesDroppedByCapability(t *testing.T) {
	before := droppedResponses(t)
	KaetzchenResponsesDropped("echo")
	KaetzchenResponsesDropped("echo")
	KaetzchenResponsesDropped("spool")
	after := droppedResponses(t)
	require.Equal(t, before["echo"]+2, after["echo"])
	require.Equal(t, before["spool"]+1, after["spool"])
}
