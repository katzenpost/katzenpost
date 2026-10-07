// SPDX-License-Identifier: AGPL-3.0-only

package epochtime

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResolvePeriod(t *testing.T) {
	for _, c := range []struct {
		name       string
		configured time.Duration
		env        string
		want       time.Duration
		fromEnv    bool
		fails      bool
	}{
		{"config only", 3 * time.Minute, "", 3 * time.Minute, false, false},
		{"config and equal env", 3 * time.Minute, "3m", 3 * time.Minute, false, false},
		{"config and equal env spelled differently", 3 * time.Minute, "180s", 3 * time.Minute, false, false},
		{"config and different env", 3 * time.Minute, "2m", 0, false, true},
		{"config and unparsable env", 3 * time.Minute, "soon", 0, false, true},
		{"config and empty env", 3 * time.Minute, "", 3 * time.Minute, false, false},
		{"env only", 0, "2m", 2 * time.Minute, true, false},
		{"env only below the bound", 0, "90s", 0, false, true},
		{"env only unparsable", 0, "soon", 0, false, true},
		{"neither", 0, "", 20 * time.Minute, false, false},
		{"config below the bound", 119 * time.Second, "", 0, false, true},
		{"config fraction of a second", 2*time.Minute + time.Millisecond, "", 0, false, true},
		{"config negative", -3 * time.Minute, "", 0, false, true},
		{"config above a week", 7*24*time.Hour + time.Second, "", 0, false, true},
		{"config at the lower bound", 2 * time.Minute, "", 2 * time.Minute, false, false},
		{"config at a week", 7 * 24 * time.Hour, "", 7 * 24 * time.Hour, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, fromEnv, err := resolvePeriod(c.configured, c.env)
			if c.fails {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, c.want, got)
			require.Equal(t, c.fromEnv, fromEnv)
		})
	}
}

func TestSetPeriodOnce(t *testing.T) {
	var v atomic.Int64
	require.NoError(t, setPeriodOnce(&v, 3*time.Minute))
	require.NoError(t, setPeriodOnce(&v, 3*time.Minute))
	require.Error(t, setPeriodOnce(&v, 2*time.Minute))
	require.Equal(t, int64(3*time.Minute), v.Load())
}

func TestValidatePeriod(t *testing.T) {
	require.NoError(t, ValidatePeriod(20*time.Minute))
	require.NoError(t, ValidatePeriod(MinPeriod))
	require.NoError(t, ValidatePeriod(MaxPeriod))
	require.Error(t, ValidatePeriod(0))
	require.Error(t, ValidatePeriod(MinPeriod-time.Second))
	require.Error(t, ValidatePeriod(MaxPeriod+time.Second))
	require.Error(t, ValidatePeriod(20*time.Minute+time.Nanosecond))
	require.Equal(t, 2*time.Minute, MinPeriod)
	require.Equal(t, 7*24*time.Hour, MaxPeriod)
}

func TestConfigureWarnsWhenTheEnvironmentDecides(t *testing.T) {
	var warn bytes.Buffer
	var v atomic.Int64
	require.NoError(t, configure(&v, 0, "2m", &warn))
	require.Equal(t, int64(2*time.Minute), v.Load())
	require.Contains(t, warn.String(), EnvironmentVariable)
	require.Contains(t, warn.String(), "EpochDuration")

	warn.Reset()
	var w atomic.Int64
	require.NoError(t, configure(&w, 3*time.Minute, "", &warn))
	require.Equal(t, int64(3*time.Minute), w.Load())
	require.Empty(t, warn.String())

	require.Error(t, configure(&w, 3*time.Minute, "2m", &warn))
	require.Error(t, configure(&w, 0, "2m", &warn))
	require.Equal(t, int64(3*time.Minute), w.Load())
}
