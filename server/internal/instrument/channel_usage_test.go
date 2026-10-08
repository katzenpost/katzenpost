// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package instrument

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func channelGauges(t *testing.T, name string) (usage, peak float64) {
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(channelUsage))
	require.NoError(t, reg.Register(channelUsageMax))
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, f := range families {
		for _, m := range f.GetMetric() {
			if m.GetLabel()[0].GetValue() != name {
				continue
			}
			switch f.GetName() {
			case "katzenpost_channel_usage":
				usage = m.GetGauge().GetValue()
			case "katzenpost_channel_usage_max":
				peak = m.GetGauge().GetValue()
			}
		}
	}
	return usage, peak
}

func TestGaugeChannelLengthKeepsThePeak(t *testing.T) {
	GaugeChannelLength("peak_test", 3)
	GaugeChannelLength("peak_test", 9)
	GaugeChannelLength("peak_test", 2)
	usage, peak := channelGauges(t, "peak_test")
	require.Equal(t, 2.0, usage)
	require.Equal(t, 9.0, peak)

	GaugeChannelLength("other_test", 1)
	_, peak = channelGauges(t, "peak_test")
	require.Equal(t, 9.0, peak)
}
