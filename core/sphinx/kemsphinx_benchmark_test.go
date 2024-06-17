// kemsphinx_benchmark_test.go - KEMSphinx Packet Format benchmarks.
// Copyright (C) 2022 David Stainton.
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
	"testing"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/adapter"
	"github.com/katzenpost/hpqc/kem/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func BenchmarkKEMSphinxUnwrapX25519(b *testing.B) {
	benchmarkKEMSphinxUnwrap(b, adapter.FromNIKE(ecdh.Scheme(rand.Reader)))
}

func BenchmarkKEMSphinxUnwrapKyber512(b *testing.B) {
	benchmarkKEMSphinxUnwrap(b, schemes.ByName("Kyber512"))
}

func BenchmarkKEMSphinxUnwrapKyber768(b *testing.B) {
	benchmarkKEMSphinxUnwrap(b, schemes.ByName("Kyber768"))
}

func BenchmarkKEMSphinxUnwrapKyber1024(b *testing.B) {
	benchmarkKEMSphinxUnwrap(b, schemes.ByName("Kyber1024"))
}

func BenchmarkKEMSphinxUnwrapKyber768X25519(b *testing.B) {
	benchmarkKEMSphinxUnwrap(b, schemes.ByName("Kyber768-X25519"))
}

func benchmarkKEMSphinxUnwrap(b *testing.B, mykem kem.Scheme) {
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

	g := geo.KEMGeometryFromUserForwardPayloadLength(mykem, len(testPayload), false, 5)
	sphinx := NewKEMSphinx(mykem, g)

	nodes, path := newBenchKEMPathVector(mykem, g.NrHops, false)
	payload := []byte(testPayload)

	pkt, err := sphinx.newKEMPacket(rand.Reader, path, payload)
	if err != nil {
		panic("wtf")
	}
	if len(pkt) != g.HeaderLength+g.PayloadTagLength+len(payload) {
		panic("wtf")
	}

	for n := 0; n < b.N; n++ {
		testPacket := make([]byte, len(pkt))
		copy(testPacket, pkt)
		_, _, _, err := sphinx.Unwrap(nodes[0].privateKey, testPacket)
		if err != nil {
			panic("wtf")
		}
	}
}

func benchNewKEMNode(mykem kem.Scheme) *kemNodeParams {
	n := new(kemNodeParams)

	_, err := rand.Reader.Read(n.id[:])
	if err != nil {
		panic("wtf")
	}
	n.publicKey, n.privateKey, err = mykem.GenerateKeyPair()
	if err != nil {
		panic("wtf")
	}
	return n
}

func newBenchKEMPathVector(mykem kem.Scheme, nrHops int, isSURB bool) ([]*kemNodeParams, []*PathHop) {
	const delayBase = 0xdeadbabe

	// Generate the keypairs and node identifiers for the "nodes".
	nodes := make([]*kemNodeParams, nrHops)
	for i := range nodes {
		nodes[i] = benchNewKEMNode(mykem)
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
			_, err := rand.Reader.Read(recipient.ID[:])
			if err != nil {
				panic(err)
			}
			path[i].Commands = append(path[i].Commands, recipient)

			// This is a SURB, add a surb_reply.
			if isSURB {
				surbReply := new(commands.SURBReply)
				_, err := rand.Reader.Read(surbReply.ID[:])
				if err != nil {
					panic(err)
				}

				path[i].Commands = append(path[i].Commands, surbReply)
			}
		}
	}

	return nodes, path
}
