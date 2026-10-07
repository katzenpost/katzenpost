// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const minimalCourierTOML = `WireKEMScheme = "x25519"
DataDir = "/var/lib/courier"

[PKI]

[SphinxGeometry]

[Logging]
Level = "INFO"
`

func TestLoadIgnoresUnknownFutureKeys(t *testing.T) {
	_, err := Load([]byte("FutureKey = \"x\"\n" + minimalCourierTOML + "\n[FutureTable]\nFutureKey = 1\n"))
	require.NoError(t, err)
}
