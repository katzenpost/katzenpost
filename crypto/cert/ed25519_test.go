// ed25519_test.go - ed25519 certificate tests.
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

package cert

import (
	"bytes"
	"testing"
	"time"

	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/assert"
)

func TestEd25519ExpiredCertificate(t *testing.T) {
	assert := assert.New(t)

	ephemeralPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	signingPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	// expiration six months ago
	expiration := time.Now().AddDate(0, -6, 0).Unix()

	certificate, err := Sign(signingPrivKey, ephemeralPrivKey.PublicKey().Bytes(), expiration)
	assert.Error(err)

	certified, err := Verify(ephemeralPrivKey.PublicKey(), certificate)
	assert.Error(err)
	assert.Nil(certified)
}

func TestEd25519Certificate(t *testing.T) {
	assert := assert.New(t)

	ephemeralPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	signingPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	// expires 600 years after unix epoch
	expiration := time.Unix(0, 0).AddDate(600, 0, 0).Unix()

	toSign := ephemeralPrivKey.PublicKey().Bytes()
	certificate, err := Sign(signingPrivKey, toSign, expiration)

	mesg, err := Verify(signingPrivKey.PublicKey(), certificate)
	assert.NoError(err)
	assert.NotNil(mesg)
	assert.Equal(mesg, toSign)
}

func TestEd25519BadCertificate(t *testing.T) {
	assert := assert.New(t)

	ephemeralPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	signingPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()

	certificate, err := Sign(signingPrivKey, ephemeralPrivKey.PublicKey().Bytes(), expiration)
	assert.NoError(err)

	mesg, err := Verify(ephemeralPrivKey.PublicKey(), certificate)
	assert.Error(err)
	assert.Nil(mesg)
}

func TestEd25519MultiSignatureCertificate(t *testing.T) {
	assert := assert.New(t)

	ephemeralPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	signingPrivKey1, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)
	signingPrivKey2, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)
	signingPrivKey3, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()

	certificate, err := Sign(signingPrivKey1, ephemeralPrivKey.PublicKey().Bytes(), expiration)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey2, certificate)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey3, certificate)
	assert.NoError(err)

	mesg, err := Verify(signingPrivKey1.PublicKey(), certificate)
	assert.NoError(err)
	assert.NotNil(mesg)

	mesg, err = Verify(signingPrivKey2.PublicKey(), certificate)
	assert.NoError(err)
	assert.NotNil(mesg)

	mesg, err = Verify(signingPrivKey3.PublicKey(), certificate)
	assert.NoError(err)
	assert.NotNil(mesg)
}

func TestEd25519MultiSignatureOrdering(t *testing.T) {
	assert := assert.New(t)

	ephemeralPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	signingPrivKey1, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)
	signingPrivKey2, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)
	signingPrivKey3, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()

	// 1
	certificate1, err := Sign(signingPrivKey1, ephemeralPrivKey.PublicKey().Bytes(), expiration)
	assert.NoError(err)
	certificate1, err = SignMulti(signingPrivKey2, certificate1)
	assert.NoError(err)
	certificate1, err = SignMulti(signingPrivKey3, certificate1)
	assert.NoError(err)

	// 2
	certificate2, err := Sign(signingPrivKey1, ephemeralPrivKey.PublicKey().Bytes(), expiration)
	assert.NoError(err)
	certificate2, err = SignMulti(signingPrivKey3, certificate2)
	assert.NoError(err)
	certificate2, err = SignMulti(signingPrivKey2, certificate2)
	assert.NoError(err)

	assert.Equal(certificate1, certificate2)

	// 3
	certificate3, err := Sign(signingPrivKey2, ephemeralPrivKey.PublicKey().Bytes(), expiration)
	assert.NoError(err)
	certificate3, err = SignMulti(signingPrivKey3, certificate3)
	assert.NoError(err)
	certificate3, err = SignMulti(signingPrivKey1, certificate3)
	assert.NoError(err)

	assert.Equal(certificate3, certificate2)
}

func TestEd25519VerifyAll(t *testing.T) {
	assert := assert.New(t)

	ephemeralPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	signingPrivKey1, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)
	signingPrivKey2, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)
	signingPrivKey3, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()

	certificate, err := Sign(signingPrivKey1, ephemeralPrivKey.PublicKey().Bytes(), expiration)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey2, certificate)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey3, certificate)
	assert.NoError(err)

	verifiers := []Verifier{signingPrivKey1.PublicKey(), signingPrivKey2.PublicKey(), signingPrivKey2.PublicKey()}
	mesg, err := VerifyAll(verifiers, certificate)
	assert.NoError(err)
	assert.NotNil(mesg)
}

func TestEd25519VerifyThreshold(t *testing.T) {
	assert := assert.New(t)

	ephemeralPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	signingPrivKey1, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)
	signingPrivKey2, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)
	signingPrivKey3, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)
	signingPrivKey4, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()

	certificate, err := Sign(signingPrivKey1, ephemeralPrivKey.PublicKey().Bytes(), expiration)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey2, certificate)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey3, certificate)
	assert.NoError(err)

	verifiers := []Verifier{signingPrivKey1.PublicKey(), signingPrivKey2.PublicKey(), signingPrivKey4.PublicKey()}
	threshold := 2
	mesg, good, bad, err := VerifyThreshold(verifiers, threshold, certificate)
	assert.NoError(err)
	assert.NotNil(mesg)
	assert.Equal(bad[0].Identity(), signingPrivKey4.Identity())
	hasVerifier := func(verifier Verifier) bool {
		for _, v := range good {
			if bytes.Equal(v.Identity(), verifier.Identity()) {
				return true
			}
		}
		return false
	}
	assert.True(hasVerifier(signingPrivKey1.PublicKey()))
	assert.True(hasVerifier(signingPrivKey2.PublicKey()))
	assert.False(hasVerifier(signingPrivKey4.PublicKey()))
}

func TestEd25519AddSignature(t *testing.T) {
	assert := assert.New(t)

	ephemeralPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	signingPrivKey1, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)
	signingPrivKey2, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()

	certificate, err := Sign(signingPrivKey1, ephemeralPrivKey.PublicKey().Bytes(), expiration)
	assert.NoError(err)

	certificate2, err := SignMulti(signingPrivKey2, certificate)
	assert.NoError(err)

	sig, err := GetSignature(signingPrivKey2.Identity(), certificate2)
	assert.NoError(err)
	assert.NotNil(sig)
	certificate3, err := AddSignature(signingPrivKey2.PublicKey(), *sig, certificate)
	assert.NoError(err)

	assert.Equal(certificate2, certificate3)
}
