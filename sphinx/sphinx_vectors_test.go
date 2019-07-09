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
	"io/ioutil"
	"testing"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/stretchr/testify/require"
	"github.com/ugorji/go/codec"
)

type hexNodeParams struct {
	ID         string
	PrivateKey string
}

type hexPathHop struct {
	ID        string
	PublicKey string
	Commands  []string
}

type hexSphinxForwardTest struct {
	Nodes   []hexNodeParams
	Path    []hexPathHop
	Packets []string
	Payload string
}

func TestBuildFileVectorForwardSphinx(t *testing.T) {
	require := require.New(t)

	hexTests := buildVectorForwardSphinx(t)

	serialized := []byte{}
	handle := new(codec.JsonHandle)
	handle.Indent = 4
	enc := codec.NewEncoderBytes(&serialized, handle)
	err := enc.Encode(hexTests)
	require.NoError(err)

	err = ioutil.WriteFile("testdata/sphinx_forward_vectors.json", serialized, 0644)
	require.NoError(err)
}

func TestVectorForwardSphinx(t *testing.T) {
	require := require.New(t)

	serialized, err := ioutil.ReadFile("testdata/sphinx_forward_vectors.json")
	require.NoError(err)

	decoder := codec.NewDecoderBytes(serialized, new(codec.JsonHandle))
	tests := []hexSphinxForwardTest{}
	err = decoder.Decode(&tests)
	require.NoError(err)

	for _, test := range tests {
		packet, err := hex.DecodeString(test.Packets[0])
		require.NoError(err)

		// Unwrap the packet, validating the output.
		for i := range test.Nodes {
			// There's no sensible way to validate that `tag` is correct.
			privateKey := new(ecdh.PrivateKey)
			rawKey, err := hex.DecodeString(test.Nodes[i].PrivateKey)
			require.NoError(err)
			err = privateKey.FromBytes(rawKey)
			require.NoError(err)
			b, _, cmds, err := Unwrap(privateKey, packet)
			require.NoErrorf(err, "Hop %d: Unwrap failed", i)

			rawPacket, err := hex.DecodeString(test.Packets[i+1])
			require.NoError(err)
			require.Equal(packet, rawPacket)

			if i == len(test.Path)-1 {
				require.Equalf(1, len(cmds), "Hop %d: Unexpected number of commands", i)
				cmd, err := hex.DecodeString(test.Path[i].Commands[0])
				require.NoError(err)
				require.EqualValuesf(cmd, cmds[0].ToBytes([]byte{}), "Hop %d: recipient mismatch", i)

				testPayload, err := hex.DecodeString(test.Payload)
				require.NoError(err)
				require.Equalf(b, testPayload, "Hop %d: payload mismatch", i)
				break
			} else {
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

func buildVectorForwardSphinx(t *testing.T) []hexSphinxForwardTest {
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

	require := require.New(t)

	tests := make([]hexSphinxForwardTest, constants.NrHops+1)
	for nrHops := 1; nrHops <= constants.NrHops; nrHops++ {

		// Generate the "nodes" and path for the forward sphinx packet.
		nodes, path := newPathVector(require, nrHops, false)
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
				PublicKey: hex.EncodeToString(hop.PublicKey.Bytes()),
				Commands:  make([]string, len(hop.Commands)),
			}
			for j, cmd := range hop.Commands {
				hexPath[i].Commands[j] = hex.EncodeToString(cmd.ToBytes([]byte{}))
			}
		}

		// Create the packet.
		payload := []byte(testPayload)
		pkt, err := NewPacket(rand.Reader, path, payload)
		require.NoError(err, "NewPacket failed")
		require.Len(pkt, HeaderLength+PayloadTagLength+len(payload), "Packet Length")
		hexPackets := make([]string, len(nodes)+1)
		hexPackets[0] = hex.EncodeToString(pkt)

		// Unwrap the packet, validating the output.
		for i := range nodes {

			// There's no sensible way to validate that `tag` is correct.
			b, _, cmds, err := Unwrap(nodes[i].privateKey, pkt)
			require.NoErrorf(err, "Hop %d: Unwrap failed", i)

			hexPackets[i+1] = hex.EncodeToString(pkt)

			if i == len(path)-1 {
				require.Equalf(1, len(cmds), "Hop %d: Unexpected number of commands", i)
				require.EqualValuesf(path[i].Commands[0], cmds[0], "Hop %d: recipient mismatch", i)

				require.Equalf(b, payload, "Hop %d: payload mismatch", i)

				hexTest := hexSphinxForwardTest{
					Nodes:   hexNodes,
					Path:    hexPath,
					Packets: hexPackets,
					Payload: hex.EncodeToString(b),
				}
				tests[nrHops] = hexTest
			} else {
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
