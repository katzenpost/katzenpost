// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlankLoggingLevelDefaults(t *testing.T) {
	l := &Logging{}
	require.NoError(t, l.validate())
	require.Equal(t, defaultLogLevel, l.Level)
	l = &Logging{Level: "debug"}
	require.NoError(t, l.validate())
	require.Equal(t, "DEBUG", l.Level)
	require.Error(t, (&Logging{Level: "loud"}).validate())
}
