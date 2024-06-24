// noise_test.go - Test for noise parameters.
// Copyright (C) 2017  David Anthony Stainton
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

package wire

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/circl/kem/kyber/kyber768"

	"github.com/katzenpost/nyquist"
	"github.com/katzenpost/nyquist/cipher"
	"github.com/katzenpost/nyquist/hash"
	nyquistkem "github.com/katzenpost/nyquist/kem"
	"github.com/katzenpost/nyquist/pattern"
	"github.com/katzenpost/nyquist/seec"

	"github.com/katzenpost/hpqc/kem/adapter"
	kemhybrid "github.com/katzenpost/hpqc/kem/hybrid"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

func TestNyquistPqNoiseParams2(t *testing.T) {
	t.Parallel()
	seecGenRand, err := seec.GenKeyPRPAES(rand.Reader, 256)
	require.NoError(t, err, "seec.GenKeyPRPAES")

	protocol := &nyquist.Protocol{
		Pattern: pattern.PqXX,
		KEM: kemhybrid.New(
			"Kyber768-X25519",
			adapter.FromNIKE(ecdh.Scheme(rand.Reader)),
			kyber768.Scheme(),
		),
		Cipher: cipher.ChaChaPoly,
		Hash:   hash.BLAKE2s,
	}

	t.Logf("KEM public key size: %d", protocol.KEM.PublicKeySize())
	t.Logf("KEM ciphertext size: %d", protocol.KEM.CiphertextSize())

	_, clientStatic := nyquistkem.GenerateKeypair(protocol.KEM, seecGenRand)

	wireVersion := []byte{0x03} // Prologue indicates version 3.
	maxMsgLen := 1048576

	clientCfg := &nyquist.HandshakeConfig{
		Protocol:       protocol,
		Rng:            rand.Reader,
		Prologue:       wireVersion,
		MaxMessageSize: maxMsgLen,
		KEM: &nyquist.KEMConfig{
			LocalStatic: clientStatic,
			GenKey:      seec.GenKeyPRPAES,
		},
		IsInitiator: true,
	}

	_, serverStatic := nyquistkem.GenerateKeypair(protocol.KEM, seecGenRand)
	serverCfg := &nyquist.HandshakeConfig{
		Protocol:       protocol,
		Rng:            rand.Reader,
		Prologue:       wireVersion,
		MaxMessageSize: maxMsgLen,
		KEM: &nyquist.KEMConfig{
			LocalStatic: serverStatic,
			GenKey:      seec.GenKeyPRPAES,
		},
		IsInitiator: false,
	}

	clientHs, err := nyquist.NewHandshake(clientCfg)
	require.NoError(t, err)
	defer clientHs.Reset()

	serverHs, err := nyquist.NewHandshake(serverCfg)
	require.NoError(t, err)
	defer serverHs.Reset()

	clientSs := clientHs.SymmetricState()
	require.NotNil(t, clientSs)

	clientCs := clientSs.CipherState()
	require.NotNil(t, clientCs)

	var (
		authLen = 1 + MaxAdditionalDataLength + 4
	)

	// (client) -> (prologue), e
	clientMsg1, err := clientHs.WriteMessage(nil, nil)
	require.NoError(t, err)

	t.Logf("len clientMsg1 %d", len(clientMsg1))

	_, err = serverHs.ReadMessage(nil, clientMsg1)
	require.NoError(t, err)

	// -> ekem, s, (auth)
	rawAuth := make([]byte, authLen)
	serverMsg1, err := serverHs.WriteMessage(nil, rawAuth)
	require.NoError(t, err)

	t.Logf("len serverMsg1 %d", len(serverMsg1))

	_, err = clientHs.ReadMessage(nil, serverMsg1)
	require.NoError(t, err)

	// -> skem, s, (auth)
	clientMsg2, err := clientHs.WriteMessage(nil, rawAuth)
	require.NoError(t, err)

	t.Logf("len clientMsg2 %d", len(clientMsg2))

	_, err = serverHs.ReadMessage(nil, clientMsg2)
	require.NoError(t, err)

	// (server) -> skem
	serverMsg2, err := serverHs.WriteMessage(nil, nil)
	require.Equal(t, nyquist.ErrDone, err)

	t.Logf("len serverMsg2 %d", len(serverMsg2))

	_, err = clientHs.ReadMessage(nil, serverMsg2)
	require.Equal(t, nyquist.ErrDone, err)

	clientStatus := clientHs.GetStatus()
	serverStatus := serverHs.GetStatus()

	require.Equal(t, clientStatus.HandshakeHash, serverStatus.HandshakeHash)

	blob1, err := clientStatus.KEM.LocalEphemeral.MarshalBinary()
	require.NoError(t, err)
	blob2, err := serverStatus.KEM.RemoteEphemeral.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, blob1, blob2)

	blob1, err = clientStatus.KEM.RemoteStatic.MarshalBinary()
	require.NoError(t, err)
	blob2, err = serverStatic.Public().MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, blob1, blob2)

	blob1, err = serverStatus.KEM.RemoteStatic.MarshalBinary()
	require.NoError(t, err)
	blob2, err = clientStatic.Public().MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, blob1, blob2)

	// Note: Unlike in normal XX, server does not generate `e`.
	require.Nil(t, clientStatus.KEM.RemoteEphemeral)
	require.Nil(t, serverStatus.KEM.LocalEphemeral)

	// send messages
	const plaintext = "I tell you: one must still have chaos in oneself in order to be able to give birth to a dancing star. I tell you: you still have chaos within you."

	_, clientrx := clientStatus.CipherStates[0], clientStatus.CipherStates[1]
	_, servertx := serverStatus.CipherStates[0], serverStatus.CipherStates[1]

	serverMsg3, err := servertx.EncryptWithAd(nil, nil, []byte(plaintext))
	assert.NoError(t, err)

	serverMsg3Plaintext, err := clientrx.DecryptWithAd(nil, nil, serverMsg3)
	assert.NoError(t, err)

	assert.Equal(t, serverMsg3Plaintext, []byte(plaintext))
}
