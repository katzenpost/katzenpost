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

func TestCheckHostGeometry(t *testing.T) {
	own := geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), 2000, true, 5)
	other := geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), 3000, true, 5)
	blob := func(g *geo.Geometry) string {
		b, err := g.Marshal()
		require.NoError(t, err)
		return string(b)
	}

	t.Setenv(cborplugin.PluginPayloadLengthEnv, "")
	t.Setenv(cborplugin.PluginGeometryEnv, "")
	require.NoError(t, checkHostGeometry(own), "an older host passes nothing")

	t.Setenv(cborplugin.PluginGeometryEnv, blob(own))
	require.NoError(t, checkHostGeometry(own))

	t.Setenv(cborplugin.PluginGeometryEnv, blob(other))
	require.ErrorContains(t, checkHostGeometry(own), "geometry")

	t.Setenv(cborplugin.PluginGeometryEnv, "")
	t.Setenv(cborplugin.PluginPayloadLengthEnv, "3000")
	require.ErrorContains(t, checkHostGeometry(own), "payload")

	t.Setenv(cborplugin.PluginPayloadLengthEnv, "2000")
	require.NoError(t, checkHostGeometry(own))
}
