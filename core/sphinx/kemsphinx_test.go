// SPDX-License-Identifier: AGPL-3.0-or-later

package sphinx

import (
	"crypto/rand"
	"testing"

	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// A non-terminal KEM hop's commands share the routing slot with the next
// hop's KEM ciphertext, so commands that reach into it must be rejected.
func TestKEMSphinxRejectsCommandsOverlappingCiphertext(t *testing.T) {
	require := require.New(t)

	scheme := kemSchemes.ByName("X25519")
	s := NewSphinx(geo.KEMGeometryFromUserForwardPayloadLength(scheme, 2000, false, 3))
	_, path := newKEMPathVector(require, scheme, 3, false)
	payload := make([]byte, s.Geometry().ForwardPayloadLength)

	// Fits: the usual NodeDelay.
	_, err := s.NewPacket(rand.Reader, path, payload)
	require.NoError(err)

	// Fits in PER_HOP_RI_LENGTH, but not alongside the next hop's ciphertext.
	path[0].Commands = append(path[0].Commands, &commands.SURBReply{})
	_, err = s.NewPacket(rand.Reader, path, payload)
	require.Error(err)
	_, _, err = s.NewSURB(rand.Reader, path)
	require.Error(err)
}
