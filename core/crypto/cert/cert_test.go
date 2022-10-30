// ed25519_test.go - ed25519 certificate tests.
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

package cert

import (
	"bytes"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpiredCertificate(t *testing.T) {
	assert := assert.New(t)

	scheme := Scheme
	_, ephemeralPubKey := scheme.NewKeypair()

	signingPrivKey, signingPubKey := scheme.NewKeypair()
	signingPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	// expiration six months ago
	expiration := time.Now().AddDate(0, -6, 0).Unix()

	certificate, err := Sign(signingPrivKey, signingPubKey, ephemeralPubKey.Bytes(), expiration)
	assert.Error(err)

	certified, err := Verify(ephemeralPubKey, certificate)
	assert.Error(err)
	assert.Nil(certified)
}

func TestCertificate(t *testing.T) {
	assert := assert.New(t)

	scheme := Scheme
	_, ephemeralPubKey := scheme.NewKeypair()

	signingPrivKey, signingPubKey := scheme.NewKeypair()

	// expires 600 years after unix epoch
	expiration := time.Unix(0, 0).AddDate(600, 0, 0).Unix()

	toSign := ephemeralPubKey.Bytes()
	certificate, err := Sign(signingPrivKey, signingPubKey, toSign, expiration)
	assert.NoError(err)

	mesg, err := Verify(signingPubKey, certificate)
	assert.NoError(err)
	assert.NotNil(mesg)
	assert.Equal(mesg, toSign)
}

func TestBadCertificate(t *testing.T) {

	signingPrivKey, signingPubKey := Scheme.NewKeypair()

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()

	certified := []byte("hello, i am a message")

	certificate, err := Sign(signingPrivKey, signingPubKey, certified, expiration)
	require.NoError(t, err)

	certificate[1000] = 235 // modify the signed data so that the Verify will fail

	mesg, err := Verify(signingPubKey, certificate)
	require.Error(t, err)
	require.Equal(t, ErrBadSignature, err)
	require.Nil(t, mesg)
}

func TestWrongCertificate(t *testing.T) {
	assert := assert.New(t)

	_, ephemeralPubKey := Scheme.NewKeypair()

	signingPrivKey, signingPubKey := Scheme.NewKeypair()

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()
	certificate, err := Sign(signingPrivKey, signingPubKey, ephemeralPubKey.Bytes(), expiration)
	assert.NoError(err)

	mesg, err := Verify(ephemeralPubKey, certificate)
	assert.Error(err)
	assert.Nil(mesg)
}

func TestMultiSignatureCertificate(t *testing.T) {
	assert := assert.New(t)

	signingPrivKey1, signingPubKey1 := Scheme.NewKeypair()
	signingPrivKey2, signingPubKey2 := Scheme.NewKeypair()
	signingPrivKey3, signingPubKey3 := Scheme.NewKeypair()

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()

	message := []byte("hi. i'm a message.")

	certificate, err := Sign(signingPrivKey1, signingPubKey1, message, expiration)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey2, signingPubKey2, certificate)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey3, signingPubKey3, certificate)
	assert.NoError(err)

	mesg, err := Verify(signingPubKey1, certificate)
	assert.NoError(err)
	assert.NotNil(mesg)

	mesg, err = Verify(signingPubKey2, certificate)
	assert.NoError(err)
	assert.NotNil(mesg)

	mesg, err = Verify(signingPubKey3, certificate)
	assert.NoError(err)
	assert.NotNil(mesg)
}

func TestVerifyAll(t *testing.T) {
	assert := assert.New(t)

	_, ephemeralPubKey := Scheme.NewKeypair()

	signingPrivKey1, signingPubKey1 := Scheme.NewKeypair()
	signingPrivKey2, signingPubKey2 := Scheme.NewKeypair()
	signingPrivKey3, signingPubKey3 := Scheme.NewKeypair()

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()

	certificate, err := Sign(signingPrivKey1, signingPubKey1, ephemeralPubKey.Bytes(), expiration)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey2, signingPubKey2, certificate)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey3, signingPubKey3, certificate)
	assert.NoError(err)

	verifiers := []Verifier{signingPubKey1, signingPubKey2, signingPubKey2}
	mesg, err := VerifyAll(verifiers, certificate)
	assert.NoError(err)
	assert.NotNil(mesg)
}

func TestVerifyThreshold(t *testing.T) {
	assert := assert.New(t)

	_, ephemeralPubKey := Scheme.NewKeypair()

	signingPrivKey1, signingPubKey1 := Scheme.NewKeypair()
	signingPrivKey2, signingPubKey2 := Scheme.NewKeypair()
	signingPrivKey3, signingPubKey3 := Scheme.NewKeypair()
	_, signingPubKey4 := Scheme.NewKeypair()

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()

	certificate, err := Sign(signingPrivKey1, signingPubKey1, ephemeralPubKey.Bytes(), expiration)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey2, signingPubKey2, certificate)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey3, signingPubKey3, certificate)
	assert.NoError(err)

	verifiers := []Verifier{signingPubKey1, signingPubKey2, signingPubKey4}
	threshold := 2
	mesg, good, bad, err := VerifyThreshold(verifiers, threshold, certificate)
	assert.NoError(err)
	assert.NotNil(mesg)
	assert.Equal(bad[0].Sum256(), signingPubKey4.Sum256())
	hasVerifier := func(verifier Verifier) bool {
		for _, v := range good {
			a := v.Sum256()
			b := verifier.Sum256()
			if bytes.Equal(a[:], b[:]) {
				return true
			}
		}
		return false
	}
	assert.True(hasVerifier(signingPubKey1))
	assert.True(hasVerifier(signingPubKey2))
	assert.False(hasVerifier(signingPubKey4))
}

func TestAddSignature(t *testing.T) {
	assert := assert.New(t)

	_, ephemeralPubKey := Scheme.NewKeypair()

	signingPrivKey1, signingPubKey1 := Scheme.NewKeypair()
	signingPrivKey2, signingPubKey2 := Scheme.NewKeypair()

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()

	certificate, err := Sign(signingPrivKey1, signingPubKey1, ephemeralPubKey.Bytes(), expiration)
	assert.NoError(err)

	certificate2, err := SignMulti(signingPrivKey2, signingPubKey2, certificate)
	assert.NoError(err)

	hash := signingPubKey2.Sum256()
	sig, err := GetSignature(hash[:], certificate2)
	assert.NoError(err)
	assert.NotNil(sig)
	certificate3, err := AddSignature(signingPubKey2, *sig, certificate)
	assert.NoError(err)

	assert.Equal(certificate2, certificate3)
}
