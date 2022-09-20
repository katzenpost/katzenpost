// dilithium_test.go - Wrapper tests.
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

// Package dilithium implements dilithium2-AES from NIST round 3
// as an implementation of our signature scheme interfaces.
package dilithium

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDilithiumSignatureScheme(t *testing.T) {
	s := Scheme
	privKey, pubKey := s.NewKeypair()
	message := []byte("hello world")
	signature := privKey.Sign(message)
	ok := pubKey.Verify(signature, message)
	require.True(t, ok)
}

func TestDilithiumBytes(t *testing.T) {
	privKey, pubKey := Scheme.NewKeypair()
	message := []byte("hello world")
	signature := privKey.Sign(message)
	pubKeyBytes := pubKey.Bytes()
	_, pubKey2 := Scheme.NewKeypair()
	err := pubKey2.FromBytes(pubKeyBytes)
	require.NoError(t, err)
	pubKeyBytes2 := pubKey2.Bytes()
	require.Equal(t, pubKeyBytes, pubKeyBytes2)
	ok := pubKey2.Verify(signature, message)
	require.True(t, ok)
}

func TestDilithiumTextMarshaler(t *testing.T) {
	privKey, pubKey := Scheme.NewKeypair()
	message := []byte("hello world")
	signature := privKey.Sign(message)

	pubKeyText, err := pubKey.MarshalText()
	require.NoError(t, err)

	_, pubKey2 := Scheme.NewKeypair()
	err = pubKey2.UnmarshalText(pubKeyText)
	require.NoError(t, err)
	require.Equal(t, pubKey2.Bytes(), pubKey.Bytes())
	ok := pubKey2.Verify(signature, message)
	require.True(t, ok)

	pubKey3, err := Scheme.UnmarshalTextPublicKey(pubKeyText)
	require.NoError(t, err)
	require.NotNil(t, pubKey3)

	_, err = pubKey3.MarshalText()
	require.NoError(t, err)

	ok = pubKey.Verify(signature, message)
	require.True(t, ok)

	ok = pubKey3.Verify(signature, message)
	require.True(t, ok)

}
