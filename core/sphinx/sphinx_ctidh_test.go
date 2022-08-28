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
)

func TestCtidhForwardSphinx(t *testing.T) {
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

	mynike := ctidhnike.NewCtidhNike()
	sphinx := NewSphinx(mynike, len(testPayload), 5)

	testForwardSphinx(t, mynike, sphinx, []byte(testPayload))
}

func TestCtidhSURB(t *testing.T) {
	const testPayload = "The smallest minority on earth is the individual.  Those who deny individual rights cannot claim to be defenders of minorities."

	mynike := ctidhnike.NewCtidhNike()
	sphinx := NewSphinx(mynike, len(testPayload), 5)

	testSURB(t, mynike, sphinx, []byte(testPayload))
}
