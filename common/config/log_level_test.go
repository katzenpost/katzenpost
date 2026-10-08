// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
)

func TestLoggingEmptyLevelDefaults(t *testing.T) {
	for _, disable := range []bool{false, true} {
		l := &Logging{Disable: disable}
		require.NoError(t, l.Validate())
		require.Equal(t, DefaultLogLevel, l.Level)
		b, err := log.New("", l.Level, l.Disable)
		require.NoError(t, err)
		require.NotNil(t, b)
	}
}

func TestLoggingLevelUppercased(t *testing.T) {
	l := &Logging{Level: "info"}
	require.NoError(t, l.Validate())
	require.Equal(t, "INFO", l.Level)
}

func TestLoggingLevelInvalid(t *testing.T) {
	l := &Logging{Level: "loud"}
	require.Error(t, l.Validate())
}
