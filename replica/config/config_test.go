// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"math"
	"testing"

	"github.com/katzenpost/katzenpost/common/config"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	c, err := LoadFile("testdata/replica.toml", false)
	require.NoError(t, err)

	if c.Logging.Level != "DEBUG" {
		panic("Logging.Level should be DEBUG")
	}

	// Test that default values are applied for new config parameters
	require.Equal(t, defaultOutgoingQueueSize, c.OutgoingQueueSize)
	require.Equal(t, defaultKeepAliveInterval, c.KeepAliveInterval)
}

func TestConfigDefaults(t *testing.T) {
	// Test that default values are applied when config values are not set
	c := &Config{}
	c.SetDefaultTimeouts()

	require.Equal(t, defaultOutgoingQueueSize, c.OutgoingQueueSize)
	require.Equal(t, defaultKeepAliveInterval, c.KeepAliveInterval)
	require.Equal(t, config.DefaultConnectTimeout, c.ConnectTimeout)
	require.Equal(t, config.DefaultHandshakeTimeout, c.HandshakeTimeout)
	require.Equal(t, config.DefaultReauthInterval, c.ReauthInterval)
}

func TestApplyRuntimeDefaults(t *testing.T) {
	tests := []struct {
		name               string
		startCfg           Config
		numCPU             int
		saturatedOpsPerSec float64
		wantProxyWorkers   int
		wantQueueSize      int
		wantTimeoutSec     int
	}{
		{
			name:               "happy path, 8-core typical CTIDH rate",
			numCPU:             8,
			saturatedOpsPerSec: 2.0,
			wantProxyWorkers:   8,
			wantQueueSize:      256, // ProxyWorkerCount*32=256 dominates burst-window 21
			wantTimeoutSec:     30,  // 30/2=15 below 30s floor
		},
		{
			name:               "single-core box, slow CTIDH",
			numCPU:             1,
			saturatedOpsPerSec: 0.5,
			wantProxyWorkers:   1,
			wantQueueSize:      64, // ProxyWorkerCount*32=32 below minBuffer=64
			wantTimeoutSec:     61, // 30/0.5+1=61 exceeds 30s floor
		},
		{
			name:               "fast host, high CTIDH rate",
			numCPU:             16,
			saturatedOpsPerSec: 100.0,
			wantProxyWorkers:   16,
			wantQueueSize:      1001, // 100*10+1=1001 exceeds ProxyWorkerCount*32=512
			wantTimeoutSec:     30,   // 30/100=0 below 30s floor
		},
		{
			name:               "zero NumCPU clamps to 1",
			numCPU:             0,
			saturatedOpsPerSec: 1.0,
			wantProxyWorkers:   1,
			wantQueueSize:      64, // ProxyWorkerCount*32=32 below minBuffer=64
			wantTimeoutSec:     31, // 30/1+1=31
		},
		{
			name:               "negative NumCPU clamps to 1",
			numCPU:             -4,
			saturatedOpsPerSec: 2.0,
			wantProxyWorkers:   1,
			wantQueueSize:      64,
			wantTimeoutSec:     30, // 30/2=15 below floor
		},
		{
			name:               "saturatedOpsPerSec=0 (self-check returned 0) falls back to floors",
			numCPU:             8,
			saturatedOpsPerSec: 0,
			wantProxyWorkers:   8,
			wantQueueSize:      256, // ProxyWorkerCount*32 dominates
			wantTimeoutSec:     30,  // floor only
		},
		{
			name:               "negative saturatedOpsPerSec treated as 0",
			numCPU:             4,
			saturatedOpsPerSec: -5,
			wantProxyWorkers:   4,
			wantQueueSize:      128, // 4*32=128 above minBuffer
			wantTimeoutSec:     30,
		},
		{
			name:               "NaN saturatedOpsPerSec treated as 0 (guard fails closed)",
			numCPU:             4,
			saturatedOpsPerSec: math.NaN(),
			wantProxyWorkers:   4,
			wantQueueSize:      128,
			wantTimeoutSec:     30,
		},
		{
			name: "operator-set values are not overwritten",
			startCfg: Config{
				ProxyWorkerCount:    32,
				IncomingQueueSize:   2048,
				ProxyRequestTimeout: 120,
			},
			numCPU:             8,
			saturatedOpsPerSec: 2.0,
			wantProxyWorkers:   32,
			wantQueueSize:      2048,
			wantTimeoutSec:     120,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.startCfg
			c.ApplyRuntimeDefaults(tc.numCPU, tc.saturatedOpsPerSec)
			require.Equal(t, tc.wantProxyWorkers, c.ProxyWorkerCount, "ProxyWorkerCount")
			require.Equal(t, tc.wantQueueSize, c.IncomingQueueSize, "IncomingQueueSize")
			require.Equal(t, tc.wantTimeoutSec, c.ProxyRequestTimeout, "ProxyRequestTimeout")
		})
	}
}
