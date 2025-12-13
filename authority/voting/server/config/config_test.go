// config_test.go - Katzenpost voting authority server configuration tests.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package config

import (
	"testing"

	"github.com/katzenpost/katzenpost/core/retry"
	"github.com/stretchr/testify/require"
)

func TestRetryDefaults(t *testing.T) {
	require := require.New(t)

	// Test that retry defaults from core/retry are sensible
	require.Greater(retry.DefaultMaxAttempts, 0, "DefaultMaxAttempts should be positive")
	require.LessOrEqual(retry.DefaultMaxAttempts, 20, "DefaultMaxAttempts should be reasonable")

	require.Greater(retry.DefaultBaseDelay.Milliseconds(), int64(0), "DefaultBaseDelay should be positive")
	require.LessOrEqual(retry.DefaultBaseDelay.Seconds(), float64(5), "DefaultBaseDelay should be <= 5s")

	require.Greater(retry.DefaultMaxDelay.Seconds(), float64(0), "DefaultMaxDelay should be positive")
	require.LessOrEqual(retry.DefaultMaxDelay.Seconds(), float64(60), "DefaultMaxDelay should be <= 60s")

	require.Greater(retry.DefaultJitter, float64(0), "DefaultJitter should be positive")
	require.LessOrEqual(retry.DefaultJitter, float64(1.0), "DefaultJitter should be <= 1.0")
}

func TestServerApplyRetryDefaults(t *testing.T) {
	require := require.New(t)

	// Test that Server.applyRetryDefaults() sets defaults correctly
	s := &Server{}
	s.applyRetryDefaults()

	require.Equal(retry.DefaultMaxAttempts, s.PeerRetryMaxAttempts,
		"PeerRetryMaxAttempts should default to retry.DefaultMaxAttempts (%d)", retry.DefaultMaxAttempts)

	require.Equal(retry.DefaultBaseDelay, s.PeerRetryBaseDelay,
		"PeerRetryBaseDelay should default to retry.DefaultBaseDelay (%v)", retry.DefaultBaseDelay)

	require.Equal(retry.DefaultMaxDelay, s.PeerRetryMaxDelay,
		"PeerRetryMaxDelay should default to retry.DefaultMaxDelay (%v)", retry.DefaultMaxDelay)

	require.Equal(retry.DefaultJitter, s.PeerRetryJitter,
		"PeerRetryJitter should default to retry.DefaultJitter (%v)", retry.DefaultJitter)
}

func TestServerRetryDefaultsNotOverwritten(t *testing.T) {
	require := require.New(t)

	// Test that applyRetryDefaults doesn't overwrite explicit values
	s := &Server{
		PeerRetryMaxAttempts: 5,
		PeerRetryBaseDelay:   100,
		PeerRetryMaxDelay:    5000,
		PeerRetryJitter:      0.5,
	}
	s.applyRetryDefaults()

	require.Equal(5, s.PeerRetryMaxAttempts, "Explicit PeerRetryMaxAttempts should not be overwritten")
	require.Equal(100, int(s.PeerRetryBaseDelay), "Explicit PeerRetryBaseDelay should not be overwritten")
	require.Equal(5000, int(s.PeerRetryMaxDelay), "Explicit PeerRetryMaxDelay should not be overwritten")
	require.Equal(0.5, s.PeerRetryJitter, "Explicit PeerRetryJitter should not be overwritten")
}
