// sphinx_test.go - Sphinx Packet Format tests.
// Copyright (C) 2022  Yawning Angel and David Stainton.
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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
)

type nodeParams struct {
	id         [constants.NodeIDLength]byte
	privateKey nike.PrivateKey
	publicKey  nike.PublicKey
}

func newNikeNode(require *require.Assertions, mynike nike.Scheme) *nodeParams {
	n := new(nodeParams)

	_, err := rand.Read(n.id[:])
	require.NoError(err, "newNikeNode(): failed to generate ID")
	n.publicKey, n.privateKey, err = mynike.GenerateKeyPair()
	require.NoError(err, "newNikeNode(): NewKeypair() failed")
	return n
}

func newNikePathVector(require *require.Assertions, mynike nike.Scheme, nrHops int, isSURB bool) ([]*nodeParams, []*PathHop) {
	const delayBase = 0xdeadbabe

	// Generate the keypairs and node identifiers for the "nodes".
	nodes := make([]*nodeParams, nrHops)
	for i := range nodes {
		nodes[i] = newNikeNode(require, mynike)
	}

	// Assemble the path vector.
	path := make([]*PathHop, nrHops)
	for i := range path {
		path[i] = new(PathHop)
		copy(path[i].ID[:], nodes[i].id[:])
		path[i].NIKEPublicKey = nodes[i].publicKey
		if i < nrHops-1 {
			// Non-terminal hop, add the delay.
			delay := new(commands.NodeDelay)
			delay.Delay = delayBase * uint32(i+1)
			path[i].Commands = append(path[i].Commands, delay)
		} else {
			// Terminal hop, add the recipient.
			recipient := new(commands.Recipient)
			_, err := rand.Read(recipient.ID[:])
			require.NoError(err, "failed to generate recipient")
			path[i].Commands = append(path[i].Commands, recipient)

			// This is a SURB, add a surb_reply.
			if isSURB {
				surbReply := new(commands.SURBReply)
				_, err := rand.Read(surbReply.ID[:])
				require.NoError(err, "failed to generate surb_reply")
				path[i].Commands = append(path[i].Commands, surbReply)
			}
		}
	}

	return nodes, path
}

func testForwardSphinx(t *testing.T, mynike nike.Scheme, sphinx *Sphinx, testPayload []byte) {
	require := require.New(t)

	for nrHops := 1; nrHops <= sphinx.Geometry().NrHops; nrHops++ {
		t.Logf("Testing %d hop(s).", nrHops)

		// Generate the "nodes" and path for the forward sphinx packet.
		nodes, path := newNikePathVector(require, mynike, nrHops, false)

		// Create the packet.
		payload := []byte(testPayload)
		pkt, err := sphinx.NewPacket(rand.Reader, path, payload)
		require.NoError(err)
		require.Equal(sphinx.Geometry().PacketLength, len(pkt))

		// Unwrap the packet, validating the output.
		for i := range nodes {
			// There's no sensible way to validate that `tag` is correct.
			b, _, cmds, err := sphinx.Unwrap(nodes[i].privateKey, pkt)
			require.NoErrorf(err, "Hop %d: Unwrap failed", i)

			if i == len(path)-1 {
				require.Equalf(1, len(cmds), "Hop %d: Unexpected number of commands", i)
				require.EqualValuesf(path[i].Commands[0], cmds[0], "Hop %d: recipient mismatch", i)

				require.Equalf(b, payload, "Hop %d: payload mismatch", i)
			} else {
				require.Equal(sphinx.Geometry().PacketLength, len(pkt))
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

func testSURB(t *testing.T, mynike nike.Scheme, sphinx *Sphinx, testPayload []byte) {
	require := require.New(t)

	for nrHops := 1; nrHops <= sphinx.Geometry().NrHops; nrHops++ {
		t.Logf("Testing %d hop(s).", nrHops)

		// Generate the "nodes" and path for the SURB.
		nodes, path := newNikePathVector(require, mynike, nrHops, true)

		// Create the SURB.
		surb, surbKeys, err := sphinx.NewSURB(rand.Reader, path)
		require.NoError(err, "NewSURB failed")
		require.Equal(sphinx.Geometry().SURBLength, len(surb), "SURB length")

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
			} else {
				require.Equal(sphinx.Geometry().PacketLength, len(pkt))
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
