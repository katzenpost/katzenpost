// lean_vectors_test.go - Cross-check the Lean port's packet *creation* side.
// Copyright (C) 2026  David Stainton.
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

	"github.com/katzenpost/hpqc/kem/adapter"
	ecdhnike "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// TestVectorSphinx (above, in sphinx_vectors_test.go) and its KEM counterpart in
// generate_kem/main.go check the Lean port's *unwrap* side: Go builds a packet, Lean unwraps
// it, bytes must match. Nothing checked the reverse -- createHeader/newNikePacket/newNikeSURB
// and their KEM equivalents are only self-consistency-tested inside Lean (nike_selftest.lean/
// kem_selftest.lean: Lean builds, Lean unwraps).
//
// testdata/lean_nike_vectors.json and testdata/lean_kem_vectors.json close that gap:
// CryptWalker/Sphinx/gen_nike_vectors.lean and gen_kem_vectors.lean build packets (and SURBs)
// with the Lean port's creation side, unwrap them with Lean's own Unwrap once as a sanity
// check, and dump the result in the same hexSphinxTest JSON shape used elsewhere. The two
// tests below unwrap those same packets with Go's real Unwrap/DecryptSURBPayload instead,
// so an independent implementation validates that Lean-created Sphinx packets are correct
// Sphinx packets -- not just that Lean agrees with itself.

func unwrapLeanVectors(t *testing.T, path string, newSphinx func(withSURB bool) *Sphinx,
	privateKeyFromHex func(hexKey string) (interface{}, error)) {
	require := require.New(t)

	serialized, err := os.ReadFile(path)
	require.NoError(err)

	tests := []hexSphinxTest{}
	err = json.Unmarshal(serialized, &tests)
	require.NoError(err)
	require.NotEmpty(tests)

	for _, test := range tests {
		packet, err := hex.DecodeString(test.Packets[0])
		require.NoError(err)

		withSURB := test.Surb != ""
		s := newSphinx(withSURB)

		for i := range test.Nodes {
			privateKey, err := privateKeyFromHex(test.Nodes[i].PrivateKey)
			require.NoError(err)

			// There's no sensible way to validate that `tag` is correct.
			b, _, cmds, err := s.Unwrap(privateKey, packet)
			require.NoErrorf(err, "Hop %d: Unwrap failed", i)

			if i == len(test.Path)-1 {
				testPayload, err := hex.DecodeString(test.Payload)
				require.NoError(err)
				if withSURB {
					require.Equalf(2, len(cmds), "SURB Hop %d: Unexpected number of commands", i)
					testSurbKeys, err := hex.DecodeString(test.SurbKeys)
					require.NoError(err)
					b, err = s.DecryptSURBPayload(b, testSurbKeys)
					require.NoError(err, "DecryptSURBPayload")
					require.Equalf(testPayload, b, "SURB Hop %d: payload mismatch", i)
				} else {
					require.Equalf(1, len(cmds), "Hop %d: Unexpected number of commands", i)
					require.Equalf(testPayload, b, "Hop %d: payload mismatch", i)
				}
			} else {
				rawPacket, err := hex.DecodeString(test.Packets[i+1])
				require.NoError(err)
				require.Equalf(rawPacket, packet, "Hop %d: forwarded packet mismatch", i)

				require.Equalf(2, len(cmds), "Hop %d: Unexpected number of commands", i)
				nextNode, ok := cmds[1].(*commands.NextNodeHop)
				require.Truef(ok, "Hop %d: cmds[1] is not a NextNodeHop", i)
				id, err := hex.DecodeString(test.Path[i+1].ID)
				require.NoError(err)
				require.Equalf(id, nextNode.ID[:], "Hop %d: NextNodeHop.ID mismatch", i)
				require.Nil(b, "Hop %d: returned payload", i)
			}
		}
	}
}

func TestLeanNikeVectors(t *testing.T) {
	mynike := ecdhnike.Scheme(rand.Reader)
	unwrapLeanVectors(t, "testdata/lean_nike_vectors.json",
		func(withSURB bool) *Sphinx {
			return NewSphinx(geo.GeometryFromUserForwardPayloadLength(mynike, 103, withSURB, 5))
		},
		func(hexKey string) (interface{}, error) {
			rawKey, err := hex.DecodeString(hexKey)
			if err != nil {
				return nil, err
			}
			privateKey := mynike.NewEmptyPrivateKey()
			if err := privateKey.FromBytes(rawKey); err != nil {
				return nil, err
			}
			return privateKey, nil
		})
}

func TestLeanKEMVectors(t *testing.T) {
	k := adapter.FromNIKEWithPRF(ecdhnike.Scheme(rand.Reader), adapter.SHA256v1)
	unwrapLeanVectors(t, "testdata/lean_kem_vectors.json",
		func(withSURB bool) *Sphinx {
			return NewKEMSphinx(k, geo.KEMGeometryFromUserForwardPayloadLength(k, 103, withSURB, 5))
		},
		func(hexKey string) (interface{}, error) {
			rawKey, err := hex.DecodeString(hexKey)
			if err != nil {
				return nil, err
			}
			return k.UnmarshalBinaryPrivateKey(rawKey)
		})
}
