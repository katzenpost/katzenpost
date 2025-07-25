// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
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

	// Test that ReplicationQueueLength is set correctly
	require.Equal(t, 100, c.ReplicationQueueLength)

	// Test that default values are applied for new config parameters
	require.Equal(t, defaultOutgoingQueueSize, c.OutgoingQueueSize)
	require.Equal(t, defaultKeepAliveInterval, c.KeepAliveInterval)
}

func TestConfigDefaults(t *testing.T) {
	// Test that default values are applied when config values are not set
	c := &Config{}
	c.setDefaultTimeouts()

	require.Equal(t, defaultReplicationQueueLength, c.ReplicationQueueLength)
	require.Equal(t, defaultOutgoingQueueSize, c.OutgoingQueueSize)
	require.Equal(t, defaultKeepAliveInterval, c.KeepAliveInterval)
	require.Equal(t, config.DefaultConnectTimeout, c.ConnectTimeout)
	require.Equal(t, config.DefaultHandshakeTimeout, c.HandshakeTimeout)
	require.Equal(t, config.DefaultReauthInterval, c.ReauthInterval)
}
