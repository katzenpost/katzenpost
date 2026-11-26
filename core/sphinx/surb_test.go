// SPDX-License-Identifier: AGPL-3.0-or-later

package sphinx

import (
	"crypto/rand"
	"testing"

	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// A reply packet must be exactly as long as a forward packet.
func TestNewPacketFromSURBPayloadLength(t *testing.T) {
	require := require.New(t)

	nikeScheme := nikeSchemes.ByName("x25519")
	nikeSphinx := NewSphinx(geo.GeometryFromUserForwardPayloadLength(nikeScheme, 2000, false, 3))
	_, nikePath := newNikePathVector(require, nikeScheme, 3, true)

	kemScheme := kemSchemes.ByName("X25519")
	kemSphinx := NewSphinx(geo.KEMGeometryFromUserForwardPayloadLength(kemScheme, 2000, false, 3))
	_, kemPath := newKEMPathVector(require, kemScheme, 3, true)

	for _, c := range []struct {
		s    *Sphinx
		path []*PathHop
	}{{nikeSphinx, nikePath}, {kemSphinx, kemPath}} {
		surb, _, err := c.s.NewSURB(rand.Reader, c.path)
		require.NoError(err)

		n := c.s.Geometry().ForwardPayloadLength
		for _, l := range []int{0, 1, n - 1, n + 1} {
			_, _, err := c.s.NewPacketFromSURB(surb, make([]byte, l))
			require.Error(err, "payload of %d bytes, expected %d", l, n)
		}
		pkt, _, err := c.s.NewPacketFromSURB(surb, make([]byte, n))
		require.NoError(err)
		require.Len(pkt, c.s.Geometry().PacketLength)
	}
}
