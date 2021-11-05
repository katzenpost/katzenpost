// deterministic_rand_test.go - Katzenpost deterministic rand.Reader tests.
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

package rand

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// XXX fix this stupid test to actually test something
func TestPerm(t *testing.T) {
	assert := assert.New(t)

	skey := [32]byte{0x00}
	rand, err := NewDeterministicRandReader(skey[:])
	assert.NoError(err, "wtf")
	rand2, err := NewDeterministicRandReader(skey[:])
	assert.NoError(err, "wtf")

	for i := 0; i < 42; i++ {
		tmp := [6]byte{}
		tmp2 := [6]byte{}
		_, err = rand.Read(tmp[:])
		assert.NoError(err, "wtf")
		_, err = rand2.Read(tmp2[:])
		assert.NoError(err, "wtf")
		assert.True(tmp == tmp2)
		t.Logf("rand values are %x", tmp)
	}
	for i := 1; i < 42; i++ {
		j := rand.Int63()
		t.Logf("%v", j)
		assert.True(j >= 0)
	}
	for i := 0; i < 42; i++ {
		p := rand.Perm(i)
		t.Logf("%v %v %v", i, len(p), p)
	}
}
