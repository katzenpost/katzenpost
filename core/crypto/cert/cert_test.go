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

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpiredCertificate(t *testing.T) {
	t.Parallel()

	scheme := Scheme
	payload := make([]byte, 123)
	_, err := rand.Reader.Read(payload)
	require.NoError(t, err)

	signingPrivKey, signingPubKey := scheme.NewKeypair()

	current, _, _ := epochtime.Now()

	certificate, err := Sign(signingPrivKey, signingPubKey, payload, current-12, current-13)
	require.NoError(t, err)
	require.NotNil(t, certificate)

	cert, err := Unmarshal(certificate)
	require.NoError(t, err)
	require.NotNil(t, cert)

	certified, err := Verify(signingPubKey, cert, current)
	require.Error(t, err)
	require.Nil(t, certified)
}

func TestCertificate(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	scheme := Scheme
	_, ephemeralPubKey := scheme.NewKeypair()

	signingPrivKey, signingPubKey := scheme.NewKeypair()

	current, _, _ := epochtime.Now()

	toSign := ephemeralPubKey.Bytes()
	certificate, err := Sign(signingPrivKey, signingPubKey, toSign, current+123, current)
	assert.NoError(err)

	cert, err := Unmarshal(certificate)
	require.NoError(t, err)

	mesg, err := Verify(signingPubKey, cert, current)
	assert.NoError(err)
	assert.NotNil(mesg)
	assert.Equal(mesg, toSign)
}

func TestBadCertificate(t *testing.T) {
	t.Parallel()

	signingPrivKey, signingPubKey := Scheme.NewKeypair()

	current, _, _ := epochtime.Now()
	validBeforeEpoch := current + 2
	// +2 so we it's not impacted by epoch rollover in between Sign()
	//  and Verify(): it's valid during [current, current+1]

	certified := []byte("hello, i am a message")

	certificate, err := Sign(signingPrivKey, signingPubKey, certified, validBeforeEpoch, current)
	require.NoError(t, err)

	// modify the signed data so that the Verify will fail.
	// XOR ensures modification:
	certificate[1000] ^= 235

	cert, err := Unmarshal(certificate)
	require.NoError(t, err)

	mesg, err := Verify(signingPubKey, cert, current)
	require.Error(t, err)
	require.Equal(t, ErrBadSignature, err)
	require.Nil(t, mesg)
}

func TestWrongCertificate(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	_, ephemeralPubKey := Scheme.NewKeypair()
	signingPrivKey, signingPubKey := Scheme.NewKeypair()

	current, _, _ := epochtime.Now()
	certificate, err := Sign(signingPrivKey, signingPubKey, ephemeralPubKey.Bytes(), current+1, current)
	assert.NoError(err)

	cert, err := Unmarshal(certificate)
	require.NoError(t, err)

	mesg, err := Verify(ephemeralPubKey, cert, current)
	assert.Error(err)
	assert.Nil(mesg)
}

func TestMultiSignatureCertificate(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	signingPrivKey1, signingPubKey1 := Scheme.NewKeypair()
	signingPrivKey2, signingPubKey2 := Scheme.NewKeypair()
	signingPrivKey3, signingPubKey3 := Scheme.NewKeypair()

	current, _, _ := epochtime.Now()

	message := []byte("hi. i'm a message.")

	certificate, err := Sign(signingPrivKey1, signingPubKey1, message, current+1, current)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey2, signingPubKey2, certificate, current)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey3, signingPubKey3, certificate, current)
	assert.NoError(err)

	cert, err := Unmarshal(certificate)
	require.NoError(t, err)

	mesg, err := Verify(signingPubKey1, cert, current)
	assert.NoError(err)
	assert.NotNil(mesg)

	mesg, err = Verify(signingPubKey2, cert, current)
	assert.NoError(err)
	assert.NotNil(mesg)

	mesg, err = Verify(signingPubKey3, cert, current)
	assert.NoError(err)
	assert.NotNil(mesg)
}

func TestVerifyThreshold(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	_, ephemeralPubKey := Scheme.NewKeypair()

	signingPrivKey1, signingPubKey1 := Scheme.NewKeypair()
	signingPrivKey2, signingPubKey2 := Scheme.NewKeypair()
	signingPrivKey3, signingPubKey3 := Scheme.NewKeypair()
	_, signingPubKey4 := Scheme.NewKeypair()

	current, _, _ := epochtime.Now()

	certificate, err := Sign(signingPrivKey1, signingPubKey1, ephemeralPubKey.Bytes(), current+1, current)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey2, signingPubKey2, certificate, current)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey3, signingPubKey3, certificate, current)
	assert.NoError(err)

	verifiers := []Verifier{signingPubKey1, signingPubKey2, signingPubKey4}
	threshold := 2

	cert, err := Unmarshal(certificate)
	require.NoError(t, err)
	mesg, good, bad, err := VerifyThreshold(verifiers, threshold, cert, current)
	assert.NoError(err)
	assert.NotNil(mesg)
	assert.Equal(len(verifiers), len(good)+len(bad))
	assert.Equal(true, len(good) >= threshold)
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
	t.Parallel()
	assert := assert.New(t)

	_, ephemeralPubKey := Scheme.NewKeypair()

	signingPrivKey1, signingPubKey1 := Scheme.NewKeypair()
	signingPrivKey2, signingPubKey2 := Scheme.NewKeypair()

	current, _, _ := epochtime.Now()

	certificate, err := Sign(signingPrivKey1, signingPubKey1, ephemeralPubKey.Bytes(), current+1, current)
	assert.NoError(err)

	certificate2, err := SignMulti(signingPrivKey2, signingPubKey2, certificate, current)
	assert.NoError(err)

	hash := signingPubKey2.Sum256()
	sig, err := GetSignature(hash[:], certificate2, current)
	assert.NoError(err)
	assert.NotNil(sig)
	certificate3, err := AddSignature(signingPubKey2, *sig, certificate, current)
	assert.NoError(err)

	assert.Equal(certificate2, certificate3)
}
