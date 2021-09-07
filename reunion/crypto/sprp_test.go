// sprp_test.go - Cryptographic primitive tests.
// Copyright (C) 2017  Yawning Angel.
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

package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSPRP(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	var key [SPRPKeyLength]byte
	_, err := rand.Read(key[:])
	require.NoError(err, "failed to read SPRP key")

	var iv [SPRPIVLength]byte
	_, err = rand.Read(iv[:])
	require.NoError(err, "failed to read SPRP IV")

	var src [1024]byte
	_, err = rand.Read(src[:])
	require.NoError(err, "failed to read source buffer")

	dst := SPRPEncrypt(&key, &iv, src[:])
	assert.NotEqual(src[:], dst, "SPRPEncrypt() did not encrypt")

	dst = SPRPDecrypt(&key, &iv, dst[:])
	assert.Equal(src[:], dst, "SPRPDecrypt() did not decrypt")
}
