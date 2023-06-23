// kemsphinx_test.go - KEMSphinx tests.
// Copyright (C) 2022  David Stainton.
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

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/hybrid"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/stretchr/testify/require"
)

type kemNodeParams struct {
	id         []byte
	privateKey kem.PrivateKey
	publicKey  kem.PublicKey
}

func TestKEMSphinxSimple(t *testing.T) {
	t.Parallel()
	mykem := hybrid.Kyber768X25519()
	withSURB := false
	g := geo.KEMGeometryFromUserForwardPayloadLength(mykem, 512, withSURB, 5)
	sphinx := NewKEMSphinx(mykem, g)
	require.NotNil(t, sphinx)
}

func TestKEMSphinxGeometry(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	withSURB := false
	g := geo.KEMGeometryFromUserForwardPayloadLength(kyber512.Scheme(), 512, withSURB, 5)
	t.Logf("KEMSphinx Kyber512 5 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(kyber512.Scheme(), 512, withSURB, 10)
	t.Logf("KEMSphinx Kyber512 10 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(kyber768.Scheme(), 512, withSURB, 5)
	t.Logf("KEMSphinx Kyber768 5 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(kyber768.Scheme(), 512, withSURB, 10)
	t.Logf("KEMSphinx Kyber768 10 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(kyber1024.Scheme(), 512, withSURB, 5)
	t.Logf("KEMSphinx Kyber1024 5 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(kyber1024.Scheme(), 512, withSURB, 10)
	t.Logf("KEMSphinx Kyber1024 10 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(hybrid.Kyber768X25519(), 512, withSURB, 5)
	t.Logf("KEMSphinx Kyber768X25519 5 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(hybrid.Kyber768X25519(), 512, withSURB, 10)
	t.Logf("KEMSphinx Kyber768X25519 10 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(hybrid.Kyber768X25519(), 512, withSURB, 20)
	t.Logf("KEMSphinx Kyber768X25519 20 hops: HeaderLength = %d", g.HeaderLength)

	mykem := hybrid.Kyber768X25519()
	withSURB = true
	payloadLen := 2000

	g = geo.KEMGeometryFromUserForwardPayloadLength(mykem, payloadLen, withSURB, 5)

	t.Logf("\n[SphinxGeometry]\n%s", g.Display())

	err := g.Validate()
	require.NoError(err)

	sphinx := NewKEMSphinx(mykem, g)
	nrHops := 5
	_, path := newKEMPathVector(require, mykem, nrHops, true)
	payload := make([]byte, g.ForwardPayloadLength)

	pkt, err := sphinx.NewPacket(rand.Reader, path, payload)
	require.NoError(err)

	t.Logf("packet length %d", len(pkt))
	t.Logf("geometry packet length %d", g.PacketLength)
	require.Equal(len(pkt), g.PacketLength)
}

func TestKEMForwardSphinx(t *testing.T) {
	t.Parallel()
	const testPayload = "Only the mob and the elite can be attracted by the momentum of totalitarianism itself. The masses have to be won by propaganda."

	mykem := hybrid.Kyber768X25519()

	g := geo.KEMGeometryFromUserForwardPayloadLength(mykem, len(testPayload), false, 20)
	sphinx := NewKEMSphinx(mykem, g)
	testForwardKEMSphinx(t, mykem, sphinx, []byte(testPayload))
}

func newKEMNode(require *require.Assertions, mykem kem.Scheme) *kemNodeParams {
	n := new(kemNodeParams)

	_, err := rand.Read(n.id[:])
	require.NoError(err)
	n.publicKey, n.privateKey, err = mykem.GenerateKeyPair()
	require.NoError(err)
	return n
}

func newKEMPathVector(require *require.Assertions, mykem kem.Scheme, nrHops int, isSURB bool) ([]*kemNodeParams, []*PathHop) {
	const delayBase = 0xdeadbabe

	// Generate the keypairs and node identifiers for the "nodes".
	nodes := make([]*kemNodeParams, nrHops)
	for i := range nodes {
		nodes[i] = newKEMNode(require, mykem)
	}

	// Assemble the path vector.
	path := make([]*PathHop, nrHops)
	for i := range path {
		path[i] = new(PathHop)
		copy(path[i].ID[:], nodes[i].id[:])
		path[i].KEMPublicKey = nodes[i].publicKey
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

func testForwardKEMSphinx(t *testing.T, mykem kem.Scheme, sphinx *Sphinx, testPayload []byte) {
	require := require.New(t)

	for nrHops := 1; nrHops <= sphinx.Geometry().NrHops; nrHops++ {
		t.Logf("Testing %d hop(s).", nrHops)

		// Generate the "nodes" and path for the forward sphinx packet.
		nodes, path := newKEMPathVector(require, mykem, nrHops, false)

		// Create the packet.
		payload := []byte(testPayload)
		pkt, err := sphinx.NewPacket(rand.Reader, path, payload)
		require.NoError(err, "NewKEMPacket failed")
		require.Equal(len(pkt), sphinx.Geometry().HeaderLength+sphinx.Geometry().PayloadTagLength+len(payload), "Packet Length")

		// Unwrap the packet, validating the output.
		for i := range nodes {
			b, _, cmds, err := sphinx.unwrapKem(nodes[i].privateKey, pkt)
			require.NoErrorf(err, "Hop %d: Unwrap failed", i)

			if i == len(path)-1 {
				require.Equalf(1, len(cmds), "Hop %d: Unexpected number of commands", i)
				require.EqualValuesf(path[i].Commands[0], cmds[0], "Hop %d: recipient mismatch", i)

				require.Equalf(b, payload, "Hop %d: payload mismatch", i)
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
}
