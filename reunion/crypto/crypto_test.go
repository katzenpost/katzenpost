// crypto_test.go - Tests.
// Copyright (C) 2019  David Stainton.
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

	"github.com/stretchr/testify/require"
)

func TestMessageTypeT1Decoding(t *testing.T) {
	require := require.New(t)
	t1 := [Type1MessageSize]byte{}
	alpha, beta, gamma, err := DecodeT1Message(t1[:])
	require.NoError(err)
	require.Equal(len(alpha), t1AlphaSize)
	require.Equal(len(beta), t1BetaSize)
	require.Equal(len(gamma), t1GammaSize)

	t1i := [Type1MessageSize + 1]byte{}
	alpha, beta, gamma, err = DecodeT1Message(t1i[:])
	require.Error(err)

	t1j := [Type1MessageSize - 1]byte{}
	alpha, beta, gamma, err = DecodeT1Message(t1j[:])
	require.Error(err)
	_, _, _ = alpha, beta, gamma
}

func TestT1Beta(t *testing.T) {
	require := require.New(t)

	var pubKey [32]byte
	_, err := rand.Read(pubKey[:])
	require.NoError(err)

	var secretKey [32]byte
	_, err = rand.Read(secretKey[:])
	require.NoError(err)

	beta, err := newT1Beta(&pubKey, &secretKey)
	require.NoError(err)

	outputKey, err := DecryptT1Beta(secretKey[:], beta)
	require.NoError(err)

	require.Equal(pubKey[:], outputKey.Bytes()[:])
}
