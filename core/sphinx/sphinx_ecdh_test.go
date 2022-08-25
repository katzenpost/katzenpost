// sphinx_test.go - Sphinx Packet Format tests.
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

package sphinx

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	ecdhnike "github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func TestEcdhForwardSphinx(t *testing.T) {
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

	require := require.New(t)
	mynike := ecdhnike.NewEcdhNike(rand.Reader)
	sphinx := NewSphinx(mynike)

	for nrHops := 1; nrHops <= constants.NrHops; nrHops++ {
		t.Logf("Testing %d hop(s).", nrHops)

		// Generate the "nodes" and path for the forward sphinx packet.
		nodes, path := newNikePathVector(require, mynike, nrHops, false)

		// Create the packet.
		payload := []byte(testPayload)
		pkt, err := sphinx.NewPacket(rand.Reader, path, payload)
		require.NoError(err, "NewPacket failed")
		require.Len(pkt, sphinx.HeaderLength()+PayloadTagLength+len(payload), "Packet Length")

		t.Logf("pkt: %s", hex.Dump(pkt))

		// Unwrap the packet, validating the output.
		for i := range nodes {
			// There's no sensible way to validate that `tag` is correct.
			b, _, cmds, err := sphinx.Unwrap(nodes[i].privateKey, pkt)
			require.NoErrorf(err, "Hop %d: Unwrap failed", i)

			if i == len(path)-1 {
				require.Equalf(1, len(cmds), "Hop %d: Unexpected number of commands", i)
				require.EqualValuesf(path[i].Commands[0], cmds[0], "Hop %d: recipient mismatch", i)

				require.Equalf(b, payload, "Hop %d: payload mismatch", i)

				t.Logf("Unwrapped payload: %v", hex.Dump(b))
			} else {
				t.Logf("Hop %d: Unwrapped pkt: %s", i, hex.Dump(pkt))

				require.Equalf(2, len(cmds), "Hop %d: Unexpected number of commands", i)
				require.EqualValuesf(path[i].Commands[0], cmds[0], "Hop %d: delay mismatch", i)

				nextNode, ok := cmds[1].(*commands.NextNodeHop)
				require.Truef(ok, "Hop %d: cmds[1] is not a NextNodeHop", i)
				require.Equalf(path[i+1].ID, nextNode.ID, "Hop %d: NextNodeHop.ID mismatch", i)

				require.Nil(b, "Hop %d: returned payload", i)
			}
		}
	}
}

func TestEcdhSURB(t *testing.T) {
	const testPayload = "The smallest minority on earth is the individual.  Those who deny individual rights cannot claim to be defenders of minorities."

	require := require.New(t)
	mynike := ecdhnike.NewEcdhNike(rand.Reader)
	sphinx := NewSphinx(mynike)

	for nrHops := 1; nrHops <= constants.NrHops; nrHops++ {
		t.Logf("Testing %d hop(s).", nrHops)

		// Generate the "nodes" and path for the SURB.
		nodes, path := newNikePathVector(require, mynike, nrHops, true)

		// Create the SURB.
		surb, surbKeys, err := sphinx.NewSURB(rand.Reader, path)
		require.NoError(err, "NewSURB failed")
		require.Equal(sphinx.SURBLength(), len(surb), "SURB length")

		// Create a reply packet using the SURB.
		payload := []byte(testPayload)
		pkt, firstHop, err := sphinx.NewPacketFromSURB(surb, payload)
		require.NoError(err, "NewPacketFromSURB failed")
		require.EqualValues(&nodes[0].id, firstHop, "NewPacketFromSURB: 0th hop")

		// Unwrap the packet, valdiating the output.
		for i := range nodes {
			// There's no sensible way to validate that `tag` is correct.
			b, _, cmds, err := sphinx.Unwrap(nodes[i].privateKey, pkt)
			require.NoErrorf(err, "SURB Hop %d: Unwrap failed", i)

			if i == len(path)-1 {
				require.Equalf(2, len(cmds), "SURB Hop %d: Unexpected number of commands", i)
				require.EqualValuesf(path[i].Commands[0], cmds[0], "SURB Hop %d: recipient mismatch", i)
				require.EqualValuesf(path[i].Commands[1], cmds[1], "SURB Hop %d: surb_reply mismatch", i)

				b, err = sphinx.DecryptSURBPayload(b, surbKeys)
				require.NoError(err, "DecrytSURBPayload")
				require.Equalf(b, payload, "SURB Hop %d: payload mismatch", i)
				t.Logf("Unwrapped payload: %v", hex.Dump(b))
			} else {
				t.Logf("Hop %d: Unwrapped pkt: %s", i, hex.Dump(pkt))

				require.Equalf(2, len(cmds), "SURB Hop %d: Unexpected number of commands", i)
				require.EqualValuesf(path[i].Commands[0], cmds[0], "SURB Hop %d: delay mismatch", i)

				nextNode, ok := cmds[1].(*commands.NextNodeHop)
				require.Truef(ok, "SURB Hop %d: cmds[1] is not a NextNodeHop", i)
				require.Equalf(path[i+1].ID, nextNode.ID, "SURB Hop %d: NextNodeHop.ID mismatch", i)

				require.Nil(b, "SURB Hop %d: returned payload", i)
			}
		}
	}
}
