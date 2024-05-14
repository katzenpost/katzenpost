// x25519_benchmark_test.go - Sphinx Packet Format benchmarks.
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

	"github.com/stretchr/testify/require"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func BenchmarkX25519SphinxUnwrap(b *testing.B) {
	benchmarkSphinxUnwrap(b, ecdh.Scheme(rand.Reader))
}

func Benchmark0knNIKESphinxUnwrap(b *testing.B) {
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

	mynike := schemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(mynike, 30000, true, 5)

	payload := make([]byte, g.ForwardPayloadLength)
	copy(payload, testPayload)

	sphinx := NewSphinx(g)
	nodes, path := benchNewPathVector(g.NrHops, true, sphinx.nike)

	pkt, err := sphinx.NewPacket(rand.Reader, path, payload)
	require.NoError(b, err)
	if len(pkt) != g.HeaderLength+g.PayloadTagLength+len(payload) {
		panic("packet length mismatch")
	}

	for n := 0; n < b.N; n++ {
		testPacket := make([]byte, len(pkt))
		copy(testPacket, pkt)
		_, _, _, err := sphinx.Unwrap(nodes[0].privateKey, testPacket)
		if err != nil {
			panic(err)
		}
	}
}

func Benchmark0knKEMSphinxUnwrap(b *testing.B) {
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

	mykem := kemschemes.ByName("MLKEM768-X25519")
	if mykem == nil {
		panic("kem is nil")
	}
	g := geo.KEMGeometryFromUserForwardPayloadLength(mykem, 30000, true, 5)
	payload := make([]byte, g.ForwardPayloadLength)
	copy(payload, testPayload)

	sphinx := NewKEMSphinx(mykem, g)

	kemnodes, kempath := newBenchKEMPathVector(mykem, g.NrHops, true)
	pkt, err := sphinx.newKEMPacket(rand.Reader, kempath, payload)
	if err != nil {
		panic("wtf")
	}
	if len(pkt) != g.HeaderLength+g.PayloadTagLength+len(payload) {
		panic("wtf")
	}

	for n := 0; n < b.N; n++ {
		testPacket := make([]byte, len(pkt))
		copy(testPacket, pkt)
		_, _, _, err := sphinx.Unwrap(kemnodes[0].privateKey, testPacket)
		if err != nil {
			panic("wtf")
		}
	}
}
