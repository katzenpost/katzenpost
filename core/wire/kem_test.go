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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

func TestSignatureScheme(t *testing.T) {
	privKey1, pubKey1 := DefaultScheme.GenerateKeypair(rand.Reader)

	pubKey2, err := DefaultScheme.UnmarshalBinaryPublicKey(pubKey1.Bytes())
	require.NoError(t, err)
	require.True(t, pubKey1.Equal(pubKey2))

	pubText, err := pubKey1.MarshalText()
	require.NoError(t, err)
	pubKey3, err := DefaultScheme.UnmarshalTextPublicKey(pubText)
	require.NoError(t, err)
	require.True(t, pubKey1.Equal(pubKey3))

	_, err = DefaultScheme.PublicKeyFromPemFile("definitelydoesnotexist")
	require.Error(t, err)

	wrongPemData := `-----BEGIN ED25519 SPHINCS+ PUBLIC KEY-----
2JQzwEwGBxBkQ0quWab4MD2T3E/WozBsfAMzp9wDLDaSm4jMADucY0gHAxX08iM3
e/o5l00d9jhM5Gr51yY5FT8acP8IdPeDS1ccwW1HTpmAWMQOJyZwvo9jwiog9IVq
-----END ED25519 SPHINCS+ PUBLIC KEY-----
`
	wrongPemPath := filepath.Join(os.TempDir(), "wrongpubkey1.pem")
	err = os.WriteFile(wrongPemPath, []byte(wrongPemData), 0666)
	require.NoError(t, err)
	_, err = DefaultScheme.PublicKeyFromPemFile(wrongPemPath)
	require.Error(t, err)

	badPemData := `-----BEGIN KYBER768-X25519 PRIVATE KEY-----
2JQzwEwGBxBkQ0quWab4MD2T3E/WozBsfAMzp9wDLDaSm4jMADucY0gHAxX08iM3
e/o5l00d9jhM5Gr51yY5FT8acP8IdPeDS1ccwW1HTpmAWMQOJyZwvo9jwiog9IVq
-----END KYBER768-X25519 PUBLIC KEY-----
`
	badPemPath := filepath.Join(os.TempDir(), "bad.pem")
	err = os.WriteFile(badPemPath, []byte(badPemData), 0666)
	require.NoError(t, err)
	_, err = DefaultScheme.PrivateKeyFromPemFile(badPemPath)
	require.Error(t, err)

	badPemData = `-----BEGIN KYBER768-X25519 PUBLIC KEY-----
2JQzwEwGBxBkQ0quWab4MD2T3E/WozBsfAMzp9wDLDaSm4jMADucY0gHAxX08iM3
e/o5l00d9jhM5Gr51yY5FT8acP8IdPeDS1ccwW1HTpmAWMQOJyZwvo9jwiog9IVq
-----END KYBER768-X25519 PUBLIC KEY-----
`
	badPemPath = filepath.Join(os.TempDir(), "badpub.pem")
	err = os.WriteFile(badPemPath, []byte(badPemData), 0666)
	require.NoError(t, err)
	_, err = DefaultScheme.PublicKeyFromPemFile(badPemPath)
	require.Error(t, err)

	pubkeypempath := filepath.Join(os.TempDir(), "pubKey1.pem")
	err = DefaultScheme.PublicKeyToPemFile(pubkeypempath, pubKey1)
	require.NoError(t, err)
	pubKey4, err := DefaultScheme.PublicKeyFromPemFile(pubkeypempath)
	require.NoError(t, err)
	require.True(t, pubKey1.Equal(pubKey4))

	_, err = DefaultScheme.PrivateKeyFromPemFile("notexit")
	require.Error(t, err)

	_, err = DefaultScheme.PrivateKeyFromPemFile(wrongPemPath)
	require.Error(t, err)

	privkeypempath := filepath.Join(os.TempDir(), "privkey2.pem")
	err = DefaultScheme.PrivateKeyToPemFile(privkeypempath, privKey1)
	require.NoError(t, err)
	privKey2, err := DefaultScheme.PrivateKeyFromPemFile(privkeypempath)
	require.NoError(t, err)
	require.Equal(t, privKey1, privKey2)
}

func TestPublicKeyReset(t *testing.T) {
	_, pubKey1 := DefaultScheme.GenerateKeypair(rand.Reader)
	pubKey1.Reset()

	require.Nil(t, pubKey1.(*publicKey).publicKey)
}

func TestPrivateKeyReset(t *testing.T) {
	privKey1, _ := DefaultScheme.GenerateKeypair(rand.Reader)
	privKey1.Reset()
	require.Nil(t, privKey1.(*privateKey).privateKey)
}

func TestPublicKeyFromBytesFailure(t *testing.T) {
	_, pubKey1 := DefaultScheme.GenerateKeypair(rand.Reader)
	err := pubKey1.FromBytes([]byte{})
	require.Error(t, err)
}

func TestPublicKeyMarshalUnmarshal(t *testing.T) {
	_, pubKey1 := DefaultScheme.GenerateKeypair(rand.Reader)

	_, pubKey2 := DefaultScheme.GenerateKeypair(rand.Reader)

	blob, err := pubKey1.MarshalBinary()
	require.NoError(t, err)
	err = pubKey2.UnmarshalBinary(blob)
	require.NoError(t, err)

	require.True(t, pubKey1.Equal(pubKey2))
}

func TestPrivateKeyMarshalUnmarshal(t *testing.T) {
	privKey1, _ := DefaultScheme.GenerateKeypair(rand.Reader)
	privKey2, _ := DefaultScheme.GenerateKeypair(rand.Reader)

	blob, err := privKey1.MarshalBinary()
	require.NoError(t, err)
	err = privKey2.UnmarshalBinary(blob)
	require.NoError(t, err)

	require.Equal(t, privKey1.Bytes(), privKey2.Bytes())
}

func TestPublicKeyMarshalUnmarshalText(t *testing.T) {
	_, pubKey1 := DefaultScheme.GenerateKeypair(rand.Reader)

	err := pubKey1.UnmarshalText(nil)
	require.Error(t, err)

	err = pubKey1.UnmarshalText([]byte{})
	require.Error(t, err)

	blob, err := pubKey1.MarshalText()
	require.NoError(t, err)
	err = pubKey1.UnmarshalText(blob)
	require.NoError(t, err)
}

func TestPrivateKeyMarshalUnmarshalText(t *testing.T) {
	privKey1, _ := DefaultScheme.GenerateKeypair(rand.Reader)
	blob, err := privKey1.MarshalText()
	require.NoError(t, err)

	privKey2, _ := DefaultScheme.GenerateKeypair(rand.Reader)
	err = privKey2.UnmarshalText(blob)
	require.NoError(t, err)

	require.Equal(t, privKey1.Bytes(), privKey2.Bytes())
}
