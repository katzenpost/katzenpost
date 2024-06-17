// sphinx_vectors_test.go - Sphinx Packet Format vector tests.
// Copyright (C) 2019  David Stainton.
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
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	ecdhnike "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const sphinxVectorsFile = "testdata/sphinx_vectors.json"

type hexNodeParams struct {
	ID         string
	PrivateKey string
}

type hexPathHop struct {
	ID        string
	PublicKey string
	Commands  []string
}

type hexSphinxTest struct {
	Nodes    []hexNodeParams
	Path     []hexPathHop
	Packets  []string
	Payload  string
	Surb     string
	SurbKeys string
}

func NoTestBuildFileVectorSphinx(t *testing.T) {
	require := require.New(t)

	mynike := ecdhnike.Scheme(rand.Reader)

	withSURB := false
	g := geo.GeometryFromUserForwardPayloadLength(mynike, 103, withSURB, 5)
	sphinx := NewSphinx(g)
	hexTests := buildVectorSphinx(t, mynike, withSURB, sphinx)
	withSURB = true
	g = geo.GeometryFromUserForwardPayloadLength(mynike, 103, withSURB, 5)
	sphinx = NewSphinx(g)
	hexTests2 := buildVectorSphinx(t, mynike, withSURB, sphinx)

	hexTests = append(hexTests, hexTests2...)

	serialized, err := json.Marshal(hexTests)
	require.NoError(err)

	err = os.WriteFile(sphinxVectorsFile, serialized, 0644)
	require.NoError(err)
}

func TestVectorSphinx(t *testing.T) {
	require := require.New(t)
	mynike := ecdhnike.Scheme(rand.Reader)

	serialized, err := os.ReadFile(sphinxVectorsFile)
	require.NoError(err)

	tests := []hexSphinxTest{}
	err = json.Unmarshal(serialized, &tests)
	require.NoError(err)

	for _, test := range tests {
		packet, err := hex.DecodeString(test.Packets[0])
		require.NoError(err)

		withSURB := false
		if test.Surb != "" {
			withSURB = true
		}
		g := geo.GeometryFromUserForwardPayloadLength(mynike, 103, withSURB, 5)
		sphinx := NewSphinx(g)

		// Unwrap the packet, validating the output.
		for i := range test.Nodes {
			// There's no sensible way to validate that `tag` is correct.
			privateKey := ecdhnike.Scheme(rand.Reader).NewEmptyPrivateKey()
			rawKey, err := hex.DecodeString(test.Nodes[i].PrivateKey)
			require.NoError(err)
			err = privateKey.FromBytes(rawKey)
			require.NoError(err)
			b, _, cmds, err := sphinx.Unwrap(privateKey, packet)
			require.NoErrorf(err, "Hop %d: Unwrap failed", i)

			if i == len(test.Path)-1 {
				if len(test.Surb) > 0 {
					require.Equalf(2, len(cmds), "SURB Hop %d: Unexpected number of commands", i)
					cmd, err := hex.DecodeString(test.Path[i].Commands[0])
					require.NoError(err)
					require.EqualValuesf(cmd, cmds[0].ToBytes([]byte{}), "Hop %d: recipient mismatch", i)
					cmd, err = hex.DecodeString(test.Path[i].Commands[1])
					require.NoError(err)
					require.EqualValuesf(cmd, cmds[1].ToBytes([]byte{}), "SURB Hop %d: surb_reply mismatch", i)

					testSurbKeys, err := hex.DecodeString(test.SurbKeys)
					require.NoError(err, "DecrytSURBPayload")
					b, err = sphinx.DecryptSURBPayload(b, testSurbKeys)
					require.NoError(err)
					testPayload, err := hex.DecodeString(test.Payload)
					require.NoError(err)
					require.Equalf(testPayload, b, "SURB Hop %d: payload mismatch", i)
				} else {
					require.Equalf(1, len(cmds), "Hop %d: Unexpected number of commands", i)
					cmd, err := hex.DecodeString(test.Path[i].Commands[0])
					require.NoError(err)
					require.EqualValuesf(cmd, cmds[0].ToBytes([]byte{}), "Hop %d: recipient mismatch", i)

					testPayload, err := hex.DecodeString(test.Payload)
					require.NoError(err)
					require.Equalf(b, testPayload, "Hop %d: payload mismatch", i)
				}
			} else {
				rawPacket, err := hex.DecodeString(test.Packets[i+1])
				require.NoError(err)
				require.Equal(packet, rawPacket)

				require.Equalf(2, len(cmds), "Hop %d: Unexpected number of commands", i)
				cmd, err := hex.DecodeString(test.Path[i].Commands[0])
				require.NoError(err)
				require.EqualValuesf(cmd, cmds[0].ToBytes([]byte{}), "Hop %d: delay mismatch", i)

				nextNode, ok := cmds[1].(*commands.NextNodeHop)
				require.Truef(ok, "Hop %d: cmds[1] is not a NextNodeHop", i)
				require.NotNil(nextNode)
				id, err := hex.DecodeString(test.Path[i+1].ID)
				require.NoError(err)
				require.Equalf(id, nextNode.ID[:], "Hop %d: NextNodeHop.ID mismatch", i)
				require.Nil(b, "Hop %d: returned payload", i)
			}
		}
	}
}

func buildVectorSphinx(t *testing.T, mynike nike.Scheme, withSURB bool, sphinx *Sphinx) []hexSphinxTest {
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

	require := require.New(t)

	tests := make([]hexSphinxTest, sphinx.Geometry().NrHops+1)
	for nrHops := 1; nrHops <= sphinx.Geometry().NrHops; nrHops++ {

		// Generate the "nodes" and path for the forward sphinx packet.
		nodes, path := newNikePathVector(require, mynike, nrHops, withSURB)
		hexNodes := make([]hexNodeParams, len(nodes))
		for i, node := range nodes {
			hexNodes[i] = hexNodeParams{
				ID:         hex.EncodeToString(node.id[:]),
				PrivateKey: hex.EncodeToString(node.privateKey.Bytes()),
			}
		}

		hexPath := make([]hexPathHop, len(path))
		for i, hop := range path {
			hexPath[i] = hexPathHop{
				ID:        hex.EncodeToString(hop.ID[:]),
				PublicKey: hex.EncodeToString(hop.NIKEPublicKey.Bytes()),
				Commands:  make([]string, len(hop.Commands)),
			}
			for j, cmd := range hop.Commands {
				hexPath[i].Commands[j] = hex.EncodeToString(cmd.ToBytes([]byte{}))
			}
		}

		// Create the packet.
		var pkt []byte
		surb := []byte{}
		surbKeys := []byte{}
		var firstHop *[32]byte
		payload := []byte(testPayload)
		var err error
		if withSURB {
			// Create the SURB.
			surb, surbKeys, err = sphinx.NewSURB(rand.Reader, path)
			require.NoError(err, "NewSURB failed")
			require.Equal(sphinx.Geometry().SURBLength, len(surb), "SURB length")

			// Create a reply packet using the SURB.
			pkt, firstHop, err = sphinx.NewPacketFromSURB(surb, payload)
			require.NoError(err, "NewPacketFromSURB failed")
			require.EqualValues(&nodes[0].id, firstHop, "NewPacketFromSURB: 0th hop")
		} else {
			pkt, err = sphinx.NewPacket(rand.Reader, path, payload)
			require.NoError(err, "NewPacket failed")
			require.Len(pkt, sphinx.Geometry().HeaderLength+sphinx.Geometry().PayloadTagLength+len(payload), "Packet Length")
		}

		tests[nrHops] = hexSphinxTest{
			Nodes:    hexNodes,
			Path:     hexPath,
			Packets:  make([]string, len(nodes)+1),
			Surb:     hex.EncodeToString(surb),
			SurbKeys: hex.EncodeToString(surbKeys),
		}
		tests[nrHops].Packets[0] = hex.EncodeToString(pkt)

		// Unwrap the packet, validating the output.
		for i := range nodes {

			// There's no sensible way to validate that `tag` is correct.
			b, _, cmds, err := sphinx.Unwrap(nodes[i].privateKey, pkt)
			require.NoErrorf(err, "Hop %d: Unwrap failed", i)

			if i == len(path)-1 {
				if withSURB {
					require.Equalf(2, len(cmds), "SURB Hop %d: Unexpected number of commands", i)
					require.EqualValuesf(path[i].Commands[0], cmds[0], "SURB Hop %d: recipient mismatch", i)
					require.EqualValuesf(path[i].Commands[1], cmds[1], "SURB Hop %d: surb_reply mismatch", i)

					b, err = sphinx.DecryptSURBPayload(b, surbKeys)
					require.NoError(err, "DecrytSURBPayload")
					require.Equalf(b, payload, "SURB Hop %d: payload mismatch", i)
				} else {
					require.Equalf(1, len(cmds), "Hop %d: Unexpected number of commands", i)
					require.EqualValuesf(path[i].Commands[0], cmds[0], "Hop %d: recipient mismatch", i)
					require.Equalf(b, payload, "Hop %d: payload mismatch", i)
				}
				tests[nrHops].Payload = hex.EncodeToString(b)
			} else {
				tests[nrHops].Packets[i+1] = hex.EncodeToString(pkt)
				require.Equalf(2, len(cmds), "Hop %d: Unexpected number of commands", i)
				require.EqualValuesf(path[i].Commands[0], cmds[0], "Hop %d: delay mismatch", i)

				nextNode, ok := cmds[1].(*commands.NextNodeHop)
				require.Truef(ok, "Hop %d: cmds[1] is not a NextNodeHop", i)
				require.Equalf(path[i+1].ID, nextNode.ID, "Hop %d: NextNodeHop.ID mismatch", i)

				require.Nil(b, "Hop %d: returned payload", i)
			}
		}
	}

	return tests[1:]
}
