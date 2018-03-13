// state.go - Katzenpost non-voting authority server state.
// Copyright (C) 2018  David Stainton.
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

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// XXX fix this stupid test to actually test something
func TestPerm(t *testing.T) {
	assert := assert.New(t)

	rand, err := NewDeterministicRandReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
	assert.NoError(err, "wtf")

	tmp := [6]byte{}
	_, err = rand.Read(tmp[:])
	assert.NoError(err, "wtf")
	t.Logf("rand val is %x", tmp)
	for i := 1; i < 42; i++ {
		j := rand.Int63()
		t.Logf("%v", j)
		assert.True(j>=0)
	}
	for i := 0; i < 42; i++ {
		t.Logf("%v", rand.Perm(i))
	}
}
