// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/rand"
	"testing"

	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

func TestCheckHostGeometryRejectsBadHostInfo(t *testing.T) {
	own := geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), 2000, true, 5)
	t.Setenv(cborplugin.PluginGeometryEnv, "")
	t.Setenv(cborplugin.PluginPayloadLengthEnv, "lots")
	require.ErrorContains(t, checkHostGeometry(own), cborplugin.PluginPayloadLengthEnv)
	t.Setenv(cborplugin.PluginPayloadLengthEnv, "")
	t.Setenv(cborplugin.PluginGeometryEnv, "not toml [")
	require.ErrorContains(t, checkHostGeometry(own), cborplugin.PluginGeometryEnv)
}
