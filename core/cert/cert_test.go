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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/schemes"
	"github.com/katzenpost/katzenpost/core/epochtime"
)

var (
	testSignatureScheme = schemes.ByName("Ed25519")
)

func TestExpiredCertificate(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	scheme := testSignatureScheme
	ephemeralPubKey, _, err := scheme.GenerateKey()
	require.NoError(t, err)

	signingPubKey, signingPrivKey, err := scheme.GenerateKey()
	require.NoError(t, err)

	current, _, _ := epochtime.Now()
	blob, err := ephemeralPubKey.MarshalBinary()
	require.NoError(t, err)

	certificate, err := Sign(signingPrivKey, signingPubKey, blob, current-12)
	require.Error(t, err)

	certified, err := Verify(ephemeralPubKey, certificate)
	assert.Error(err)
	assert.Nil(certified)
}

func TestCertificate(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	scheme := testSignatureScheme
	ephemeralPubKey, _, err := scheme.GenerateKey()
	require.NoError(t, err)

	signingPubKey, signingPrivKey, err := scheme.GenerateKey()
	require.NoError(t, err)

	current, _, _ := epochtime.Now()

	toSign, err := ephemeralPubKey.MarshalBinary()
	require.NoError(t, err)

	certificate, err := Sign(signingPrivKey, signingPubKey, toSign, current+123)
	assert.NoError(err)

	mesg, err := Verify(signingPubKey, certificate)
	assert.NoError(err)
	assert.NotNil(mesg)
	assert.Equal(mesg, toSign)
}

func TestBadCertificate(t *testing.T) {
	t.Parallel()

	signingPubKey, signingPrivKey, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)

	current, _, _ := epochtime.Now()
	validBeforeEpoch := current + 2
	// +2 so we it's not impacted by epoch rollover in between Sign()
	//  and Verify(): it's valid during [current, current+1]

	certified := []byte("hello, i am a message")

	certificate, err := Sign(signingPrivKey, signingPubKey, certified, validBeforeEpoch)
	require.NoError(t, err)

	// modify the signed data so that the Verify will fail.
	// XOR ensures modification:
	certificate[0] ^= 235

	mesg, err := Verify(signingPubKey, certificate)
	require.Error(t, err)
	require.Nil(t, mesg)
}

func TestWrongCertificate(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	ephemeralPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)

	signingPubKey, signingPrivKey, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)

	current, _, _ := epochtime.Now()
	blob, err := ephemeralPubKey.MarshalBinary()
	require.NoError(t, err)
	certificate, err := Sign(signingPrivKey, signingPubKey, blob, current+1)
	assert.NoError(err)

	mesg, err := Verify(ephemeralPubKey, certificate)
	assert.Error(err)
	assert.Nil(mesg)
}

func TestMultiSignatureCertificate(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	signingPubKey1, signingPrivKey1, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)
	signingPubKey2, signingPrivKey2, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)
	signingPubKey3, signingPrivKey3, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)

	current, _, _ := epochtime.Now()

	message := []byte("hi. i'm a message.")

	certificate, err := Sign(signingPrivKey1, signingPubKey1, message, current+1)
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
	t.Parallel()
	assert := assert.New(t)

	ephemeralPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)

	signingPubKey1, signingPrivKey1, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)
	signingPubKey2, signingPrivKey2, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)
	signingPubKey3, signingPrivKey3, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)

	current, _, _ := epochtime.Now()

	blob, err := ephemeralPubKey.MarshalBinary()
	require.NoError(t, err)

	certificate, err := Sign(signingPrivKey1, signingPubKey1, blob, current+2)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey2, signingPubKey2, certificate)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey3, signingPubKey3, certificate)
	assert.NoError(err)

	verifiers := []sign.PublicKey{signingPubKey1, signingPubKey2, signingPubKey2}
	mesg, err := VerifyAll(verifiers, certificate)
	assert.NoError(err)
	assert.NotNil(mesg)
}

func TestVerifyThreshold(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	ephemeralPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)

	signingPubKey1, signingPrivKey1, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)
	signingPubKey2, signingPrivKey2, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)
	signingPubKey3, signingPrivKey3, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)
	signingPubKey4, _, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)

	current, _, _ := epochtime.Now()

	blob, err := ephemeralPubKey.MarshalBinary()
	certificate, err := Sign(signingPrivKey1, signingPubKey1, blob, current+1)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey2, signingPubKey2, certificate)
	assert.NoError(err)

	certificate, err = SignMulti(signingPrivKey3, signingPubKey3, certificate)
	assert.NoError(err)

	verifiers := []sign.PublicKey{signingPubKey1, signingPubKey2, signingPubKey4}
	threshold := 2
	mesg, good, bad, err := VerifyThreshold(verifiers, threshold, certificate)
	assert.NoError(err)
	assert.NotNil(mesg)
	assert.Equal(len(verifiers), len(good)+len(bad))
	assert.Equal(true, len(good) >= threshold)
	assert.Equal(hash.Sum256From(bad[0]), hash.Sum256From(signingPubKey4))
	hasVerifier := func(verifier sign.PublicKey) bool {
		for _, v := range good {
			a := hash.Sum256From(v)
			b := hash.Sum256From(verifier)
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

	ephemeralPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)

	signingPubKey1, signingPrivKey1, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)
	signingPubKey2, signingPrivKey2, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)

	current, _, _ := epochtime.Now()

	blob, err := ephemeralPubKey.MarshalBinary()
	require.NoError(t, err)

	certificate, err := Sign(signingPrivKey1, signingPubKey1, blob, current+1)
	assert.NoError(err)

	certificate2, err := SignMulti(signingPrivKey2, signingPubKey2, certificate)
	assert.NoError(err)

	h := hash.Sum256From(signingPubKey2)
	sig, err := GetSignature(h[:], certificate2)
	assert.NoError(err)
	assert.NotNil(sig)
	certificate3, err := AddSignature(signingPubKey2, *sig, certificate)
	assert.NoError(err)

	assert.Equal(certificate2, certificate3)
}
