//go:build ctidh
// +build ctidh

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
	"testing"

	ctidhnike "github.com/katzenpost/katzenpost/core/crypto/nike/ctidh"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func TestCtidhForwardSphinx(t *testing.T) {
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

	mynike := ctidhnike.CTIDHScheme
	geo := geo.GeometryFromUserForwardPayloadLength(mynike, len(testPayload), false, 5)
	sphinx := NewSphinx(geo)
	sphinx.nike = mynike // XXX fixes sphinx, currently schemes.ByName doesn't
	// return CTIDH NIKE because it's guarded by the ctidh build tag for now.

	testForwardSphinx(t, mynike, sphinx, []byte(testPayload))
}

func TestCtidhSURB(t *testing.T) {
	const testPayload = "The smallest minority on earth is the individual.  Those who deny individual rights cannot claim to be defenders of minorities."

	mynike := ctidhnike.CTIDHScheme
	geo := geo.GeometryFromUserForwardPayloadLength(mynike, len(testPayload), false, 5)
	sphinx := NewSphinx(geo)
	sphinx.nike = mynike // XXX fixes sphinx, currently schemes.ByName doesn't
	// return CTIDH NIKE because it's guarded by the ctidh build tag for now.

	testSURB(t, mynike, sphinx, []byte(testPayload))
}

func TestCTIDHSphinxGeometry(t *testing.T) {
	withSURB := false
	g := geo.GeometryFromUserForwardPayloadLength(ctidhnike.CTIDHScheme, 512, withSURB, 5)
	t.Logf("NIKE Sphinx CTIDH 5 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.GeometryFromUserForwardPayloadLength(ctidhnike.CTIDHScheme, 512, withSURB, 10)
	t.Logf("NIKE Sphinx CTIDH 5 hops: HeaderLength = %d", g.HeaderLength)
}
