// eddsa_test.go - Test eddsa wrapper signature scheme tests.
//
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

package eddsa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEddsaScheme(t *testing.T) {
	message := []byte("hello world")
	privKey, pubKey := Scheme.NewKeypair()
	signature := privKey.Sign(message)
	require.Equal(t, len(signature), Scheme.SignatureSize())
	ok := pubKey.Verify(signature, message)
	require.True(t, ok)

}

func TestEddsaSchemeTextUnmarshaler(t *testing.T) {
	message := []byte("hello world")
	privKey, pubKey := Scheme.NewKeypair()

	pubKeyText, err := pubKey.MarshalText()
	require.NoError(t, err)

	pubKey2, err := Scheme.UnmarshalTextPublicKey(pubKeyText)
	require.NoError(t, err)

	signature := privKey.Sign(message)
	ok := pubKey.Verify(signature, message)
	require.True(t, ok)

	ok = pubKey2.Verify(signature, message)
	require.True(t, ok)
}
