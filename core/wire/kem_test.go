// kem_test.go - Wire protocol session KEM interfaces tests.
// Copyright (C) 2022  David Anthony Stainton
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

// Package wire implements the Katzenpost wire protocol.
package wire

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

func TestSignatureScheme(t *testing.T) {
	privKey1 := DefaultScheme.GenerateKeypair(rand.Reader)
	pubKey1 := privKey1.PublicKey()

	pubKey2, err := DefaultScheme.UnmarshalBinaryPublicKey(pubKey1.Bytes())
	require.NoError(t, err)
	require.True(t, pubKey1.Equal(pubKey2))

	pubText, err := pubKey1.MarshalText()
	require.NoError(t, err)
	pubKey3, err := DefaultScheme.UnmarshalTextPublicKey(pubText)
	require.NoError(t, err)
	require.True(t, pubKey1.Equal(pubKey3))
}
