// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInternalTransports(t *testing.T) {
	for _, line := range []string{
		`InternalTransports = ["quic", "tcp4"]`,
		`InternalTransports = ["tcp6"]`,
	} {
		_, err := Load([]byte(serverTOML(t, "  "+line+"\n")))
		require.NoError(t, err, line)
	}
	for _, line := range []string{
		`InternalTransports = []`,
		`InternalTransports = ["udp"]`,
		`InternalTransports = ["onion"]`,
		`InternalTransports = ["quic", "tcp4", "quic"]`,
	} {
		_, err := Load([]byte(serverTOML(t, "  "+line+"\n")))
		require.ErrorContains(t, err, "InternalTransports", line)
	}
}
