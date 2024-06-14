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

	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/stretchr/testify/require"
)

func TestKEMSphinxSimple(t *testing.T) {
	t.Parallel()
	mykem := schemes.ByName("Kyber768-X25519")
	withSURB := false
	g := geo.KEMGeometryFromUserForwardPayloadLength(mykem, 512, withSURB, 5)
	sphinx := NewKEMSphinx(mykem, g)
	require.NotNil(t, sphinx)
}

func TestKEMSphinxGeometry(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	withSURB := false
	g := geo.KEMGeometryFromUserForwardPayloadLength(schemes.ByName("Kyber512"), 512, withSURB, 5)
	t.Logf("KEMSphinx Kyber512 5 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(schemes.ByName("Kyber512"), 512, withSURB, 10)
	t.Logf("KEMSphinx Kyber512 10 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(schemes.ByName("Kyber768"), 512, withSURB, 5)
	t.Logf("KEMSphinx Kyber768 5 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(schemes.ByName("Kyber768"), 512, withSURB, 10)
	t.Logf("KEMSphinx Kyber768 10 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(schemes.ByName("Kyber1024"), 512, withSURB, 5)
	t.Logf("KEMSphinx Kyber1024 5 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(schemes.ByName("Kyber1024"), 512, withSURB, 10)
	t.Logf("KEMSphinx Kyber1024 10 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(schemes.ByName("Kyber768-X25519"), 512, withSURB, 5)
	t.Logf("KEMSphinx Kyber768X25519 5 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(schemes.ByName("Kyber768-X25519"), 512, withSURB, 10)
	t.Logf("KEMSphinx Kyber768X25519 10 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.KEMGeometryFromUserForwardPayloadLength(schemes.ByName("Kyber768-X25519"), 512, withSURB, 20)
	t.Logf("KEMSphinx Kyber768X25519 20 hops: HeaderLength = %d", g.HeaderLength)

	mykem := schemes.ByName("Kyber768-X25519")
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

	mykem := schemes.ByName("Kyber768-X25519")

	g := geo.KEMGeometryFromUserForwardPayloadLength(mykem, len(testPayload), false, 20)
	sphinx := NewKEMSphinx(mykem, g)
	testForwardKEMSphinx(t, mykem, sphinx, []byte(testPayload))
}

func TestKEMSphinxSURB(t *testing.T) {
	t.Parallel()
	const testPayload = "The smallest minority on earth is the individual.  Those who deny individual rights cannot claim to be defenders of minorities."

	mykem := schemes.ByName("Kyber768-X25519")
	g := geo.KEMGeometryFromUserForwardPayloadLength(mykem, len(testPayload), false, 20)
	sphinx := NewKEMSphinx(mykem, g)
	testSURBKEMSphinx(t, mykem, sphinx, []byte(testPayload))
}
