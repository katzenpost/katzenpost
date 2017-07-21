// crypto_test.go - Cryptographic primitive tests.
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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHash(t *testing.T) {
	assert := assert.New(t)

	var src [1024]byte
	_, err := rand.Read(src[:])
	require.NoError(t, err, "failed to read source buffer")

	expected := sha512.Sum512_256(src[:])
	actual := Hash(src[:])
	assert.Equal(HashLength, len(actual), "Hash() returned unexpected size digest")
	assert.Equal(expected, actual, "Hash() mismatch against SHA512-256")
}

func TestMAC(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	var key [MACKeyLength]byte
	_, err := rand.Read(key[:])
	require.NoError(err, "failed to read MAC key")

	var src [1024]byte
	_, err = rand.Read(src[:])
	require.NoError(err, "failed to read source buffer")

	eM := hmac.New(sha256.New, key[:])
	eM.Write(src[:])
	expected := eM.Sum(nil)
	expected = expected[:MACLength]

	m := NewMAC(&key)
	n, err := m.Write(src[:])
	assert.Equal(len(src), n, "Write() returned unexpected length")
	assert.NoError(err, "failed to write MAC data")
	actual := m.Sum(nil)
	assert.Equal(expected, actual, "Sum() mismatch against HMAC-SHA256-128")

	prefix := []byte("Append Test Prefix")
	expected = append(prefix, expected...)
	actual = m.Sum(prefix)
	assert.Equal(expected, actual, "Sum(prefix) mismatch against HMAC-SHA256-128")

	m.Reset()
	actual = m.Sum(nil)
	assert.NotEqual(expected, actual, "Reset() did not appear to clear state")
}

func TestStream(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	var key [StreamKeyLength]byte
	_, err := rand.Read(key[:])
	require.NoError(err, "failed to read Stream key")

	var iv [StreamIVLength]byte
	_, err = rand.Read(iv[:])
	require.NoError(err, "failed to read Stream IV")

	s := NewStream(&key, &iv)

	var expected, actual [1024]byte
	blk, err := aes.NewCipher(key[:])
	require.NoError(err, "failed to initialize crypto/aes")
	ctr := cipher.NewCTR(blk, iv[:])

	ctr.XORKeyStream(expected[:], expected[:])
	s.KeyStream(actual[:])
	assert.Equal(expected, actual, "KeyStream() mismatch against CTR-AES128")

	ctr.XORKeyStream(expected[:], expected[:])
	s.XORKeyStream(actual[:], actual[:])
	assert.Equal(expected, actual, "XORKeyStream() mismatch against CTR-AES128")

	s.Reset()
}

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

func TestKDF(t *testing.T) {
	assert := assert.New(t)

	var ikm [GroupElementLength]byte
	okm := hkdfExpand(sha256.New, ikm[:], []byte(kdfInfo), okmLength)

	k := KDF(&ikm)
	require.Equal(t, okm[:MACKeyLength], k.HeaderMAC[:])
	okm = okm[MACKeyLength:]
	assert.Equal(okm[:StreamKeyLength], k.HeaderEncryption[:])
	okm = okm[StreamKeyLength:]
	assert.Equal(okm[:StreamIVLength], k.HeaderEncryptionIV[:])
	okm = okm[StreamIVLength:]
	assert.Equal(okm[:SPRPKeyLength], k.PayloadEncryption[:])
	okm = okm[SPRPKeyLength:]
	assert.Equal(okm, k.BlindingFactor[:])

	k.Reset()
	assert.Zero(k.HeaderMAC)
	assert.Zero(k.HeaderEncryption)
	assert.Zero(k.HeaderEncryptionIV)
	assert.Zero(k.PayloadEncryption)
	assert.Zero(k.BlindingFactor)
}
