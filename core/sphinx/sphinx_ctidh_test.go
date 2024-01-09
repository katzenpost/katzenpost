// sphinx_ctidh_test.go - Sphinx Packet Format tests.
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

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh"
	ecdhnike "github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/nike/hybrid"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func TestHybridCtidhForwardSphinx(t *testing.T) {
	t.Parallel()
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

	mynike := hybrid.CTIDH1024X25519
	g := geo.GeometryFromUserForwardPayloadLength(mynike, len(testPayload), false, 5)

	t.Logf("NIKE: %s", g.NIKEName)
	t.Logf("KEM: %s", g.KEMName)

	sphinx := NewNIKESphinx(mynike, g)

	testForwardSphinx(t, mynike, sphinx, []byte(testPayload))
}

func TestSphinxConstruction(t *testing.T) {
	var mynike nike.Scheme
	mynike = ecdhnike.NewEcdhNike(rand.Reader)
	g := geo.GeometryFromUserForwardPayloadLength(mynike, 12345, false, 5)
	t.Logf("NIKEName %s", g.NIKEName)
	sphinx := NewSphinx(g)
	require.NotNil(t, sphinx.nike)

	/* XXX this code panics if CTIDH1024Scheme isn't included in the
	   NIKE Scheme map in the nike/schemes module.

			mynike = ctidh.CTIDH1024Scheme
			g = geo.GeometryFromUserForwardPayloadLength(mynike, 12345, false, 5)
			t.Logf("NIKEName %s", g.NIKEName)
			sphinx = NewSphinx(g)
			require.NotNil(t, sphinx.nike)
	*/
}

func TestCtidhForwardSphinx(t *testing.T) {
	t.Parallel()
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

	mynike := ctidh.CTIDH1024Scheme
	geo := geo.GeometryFromUserForwardPayloadLength(mynike, len(testPayload), false, 5)
	sphinx := NewNIKESphinx(mynike, geo)

	testForwardSphinx(t, mynike, sphinx, []byte(testPayload))
}

func TestCtidhSURB(t *testing.T) {
	t.Parallel()
	const testPayload = "The smallest minority on earth is the individual.  Those who deny individual rights cannot claim to be defenders of minorities."

	mynike := ctidh.CTIDH1024Scheme
	geo := geo.GeometryFromUserForwardPayloadLength(mynike, len(testPayload), false, 5)
	sphinx := NewNIKESphinx(mynike, geo)

	testSURB(t, mynike, sphinx, []byte(testPayload))
}

func TestCTIDHSphinxGeometry(t *testing.T) {
	t.Parallel()
	withSURB := false
	g := geo.GeometryFromUserForwardPayloadLength(ctidh.CTIDH1024Scheme, 512, withSURB, 5)
	t.Logf("NIKE Sphinx CTIDH 5 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.GeometryFromUserForwardPayloadLength(ctidh.CTIDH1024Scheme, 512, withSURB, 10)
	t.Logf("NIKE Sphinx CTIDH 10 hops: HeaderLength = %d", g.HeaderLength)
}
