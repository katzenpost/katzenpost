// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func TestCheckGeometryHash(t *testing.T) {
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)
	other := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2001, true, 5)

	matching := &Document{SphinxGeometryHash: g.Hash()}
	require.NoError(t, matching.CheckGeometryHash(g.Hash()))

	mismatched := &Document{SphinxGeometryHash: other.Hash()}
	require.ErrorIs(t, mismatched.CheckGeometryHash(g.Hash()), ErrGeometryMismatch)

	absent := &Document{}
	require.ErrorIs(t, absent.CheckGeometryHash(g.Hash()), ErrGeometryMismatch)
}
