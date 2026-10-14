// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func requireJittered(t *testing.T, next func() *quic.Config, period time.Duration, jitter float64) {
	t.Helper()
	lo := time.Duration(float64(period) * (1 - jitter))
	hi := time.Duration(float64(period) * (1 + jitter))
	seen := make(map[time.Duration]bool)
	for range 200 {
		cfg := next()
		require.EqualValues(t, 1, cfg.MaxIncomingStreams)
		require.EqualValues(t, -1, cfg.MaxIncomingUniStreams)
		require.Equal(t, Config().MaxIdleTimeout, cfg.MaxIdleTimeout)
		require.GreaterOrEqual(t, cfg.KeepAlivePeriod, lo)
		require.LessOrEqual(t, cfg.KeepAlivePeriod, hi)
		seen[cfg.KeepAlivePeriod] = true
	}
	if jitter == 0 {
		require.Len(t, seen, 1)
	} else {
		require.Greater(t, len(seen), 1, "the keepalive period did not vary")
	}
}

func TestKeepAlive(t *testing.T) {
	period, none, tenth := 45*time.Second, 0.0, 0.1
	for _, c := range []struct {
		name   string
		opts   *Options
		period time.Duration
		jitter float64
	}{
		{"server default", nil, 45 * time.Second, 0.25},
		{"client default", (*Options)(nil).ForClient(), 20 * time.Second, 0.25},
		{"server override", &Options{KeepAlivePeriod: &period, KeepAliveJitter: &tenth}, period, 0.1},
		{"client override", (&Options{KeepAlivePeriod: &period}).ForClient(), period, 0.25},
		{"no jitter", &Options{KeepAliveJitter: &none}, 45 * time.Second, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			requireJittered(t, c.opts.quicConfig, c.period, c.jitter)
			listen := c.opts.quicConfig()
			require.NotNil(t, listen.GetConfigForClient, "a listener must draw each connection's keepalive")
			requireJittered(t, func() *quic.Config {
				cfg, err := listen.GetConfigForClient(&quic.ClientInfo{})
				require.NoError(t, err)
				return cfg
			}, c.period, c.jitter)
		})
	}
}

func TestDefaultKeepAliveJitterFitsUnderTheIdleCap(t *testing.T) {
	idleCap := Config().MaxIdleTimeout / 2
	for name, opts := range map[string]*Options{"server": nil, "client": (*Options)(nil).ForClient()} {
		for range 200 {
			period := opts.quicConfig().KeepAlivePeriod
			require.Positive(t, period, name)
			require.Less(t, period, idleCap, "%s keepalives above half the idle timeout are capped, so the jitter has no effect", name)
		}
	}
}
