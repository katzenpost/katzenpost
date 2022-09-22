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

	"github.com/katzenpost/nyquist"
	"github.com/katzenpost/nyquist/cipher"
	"github.com/katzenpost/nyquist/hash"
	"github.com/katzenpost/nyquist/kem"
	"github.com/katzenpost/nyquist/pattern"
	"github.com/katzenpost/nyquist/seec"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/noise"
)

func TestNyquistPqNoiseParams2(t *testing.T) {
	seecGenRand, err := seec.GenKeyPRPAES(rand.Reader, 256)
	require.NoError(t, err, "seec.GenKeyPRPAES")

	protocol := &nyquist.Protocol{
		Pattern: pattern.PqXX,
		KEM:     kem.Kyber768X25519,
		Cipher:  cipher.ChaChaPoly,
		Hash:    hash.BLAKE2s,
	}

	t.Logf("KEM public key size: %d", protocol.KEM.PublicKeySize())
	t.Logf("KEM ciphertext size: %d", protocol.KEM.CiphertextSize())

	clientStatic, err := protocol.KEM.GenerateKeypair(seecGenRand)
	require.NoError(t, err)

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

	serverStatic, err := protocol.KEM.GenerateKeypair(seecGenRand)
	require.NoError(t, err)
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
	require.Equal(t, clientStatus.KEM.LocalEphemeral.Bytes(), serverStatus.KEM.RemoteEphemeral.Bytes())
	require.Equal(t, clientStatus.KEM.RemoteStatic.Bytes(), serverStatic.Public().Bytes())
	require.Equal(t, serverStatus.KEM.RemoteStatic.Bytes(), clientStatic.Public().Bytes())
	// Note: Unlike in normal XX, server does not generate `e`.
	require.Nil(t, clientStatus.KEM.RemoteEphemeral)
	require.Nil(t, serverStatus.KEM.LocalEphemeral)

}

func TestNoiseParams1(t *testing.T) {
	assert := assert.New(t)

	clientStaticKeypair, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	clientConfig := noise.Config{}
	clientConfig.CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	clientConfig.Random = rand.Reader
	clientConfig.Pattern = noise.HandshakeNN
	clientConfig.Initiator = true
	clientConfig.Prologue = []byte{0}
	clientConfig.StaticKeypair = clientStaticKeypair
	clientConfig.EphemeralKeypair, _ = noise.DH25519.GenerateKeypair(rand.Reader)
	clientHs, err := noise.NewHandshakeState(clientConfig)
	assert.NoError(err, "client NewHandshakeState")

	serverStaticKeypair, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	serverConfig := noise.Config{}
	serverConfig.CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	serverConfig.Random = rand.Reader
	serverConfig.Pattern = noise.HandshakeNN
	serverConfig.Initiator = false
	serverConfig.Prologue = []byte{0}
	serverConfig.StaticKeypair = serverStaticKeypair
	serverConfig.EphemeralKeypair, _ = noise.DH25519.GenerateKeypair(rand.Reader)
	serverHs, err := noise.NewHandshakeState(serverConfig)
	assert.NoError(err, "server NewHandshakeState")

	// handshake phase
	clientHsMsg, _, _, err := clientHs.WriteMessage(nil, nil)
	assert.NoError(err, "clientHs WriteMessage")
	assert.Equal(32, len(clientHsMsg), "client handshake message is unexpected size")

	serverHsResult, _, _, err := serverHs.ReadMessage(nil, clientHsMsg)
	assert.NoError(err, "server failed to read client handshake message")
	assert.Equal(0, len(serverHsResult), "server result message is unexpected size")

	serverHsMsg, csR0, csR1, err := serverHs.WriteMessage(nil, nil)
	assert.NoError(err, "serverHs WriteMessage")
	assert.Equal(48, len(serverHsMsg), "server handshake message is unexpected size")

	clientHsResult, csI0, csI1, err := clientHs.ReadMessage(nil, serverHsMsg)
	assert.NoError(err, "client failed to read server handshake message")
	assert.Equal(0, len(clientHsResult), "client result message is unexpected size")

	// data transfer phase
	clientMessage := []byte("hello")
	msg, err := csI0.Encrypt(nil, nil, clientMessage)
	assert.NoError(err)
	res, err := csR0.Decrypt(nil, nil, msg)
	assert.NoError(err, "Decrypt should not have failed")
	assert.Equal(clientMessage, res, "server received unexpected message")

	serverMessage := []byte("bye")
	msg, err = csR1.Encrypt(nil, nil, serverMessage)
	assert.NoError(err)
	res, err = csI1.Decrypt(nil, nil, msg)
	assert.NoError(err, "Decrypt should not have failed")
	assert.Equal(serverMessage, res, "client received unexpected message")

	serverMessage = []byte("bye bye")
	msg, err = csR1.Encrypt(nil, nil, serverMessage)
	assert.NoError(err)
	res, err = csI1.Decrypt(nil, nil, msg)
	assert.NoError(err, "Decrypt should not have failed")
	assert.Equal(serverMessage, res, "client received unexpected message")

	clientMessage = []byte("hello again")
	msg, err = csI0.Encrypt(nil, nil, clientMessage)
	assert.NoError(err)
	res, err = csR0.Decrypt(nil, nil, msg)
	assert.NoError(err, "Decrypt should not have failed")
	assert.Equal(clientMessage, res, "server received unexpected message")

	serverMessage = []byte("bye again")
	msg, err = csR1.Encrypt(nil, nil, serverMessage)
	assert.NoError(err)
	res, err = csI1.Decrypt(nil, nil, msg)
	assert.NoError(err, "Decrypt should not have failed")
	assert.Equal(serverMessage, res, "client received unexpected message")
}

func TestNoiseParams2(t *testing.T) {
	assert := assert.New(t)

	const plaintext = "Ich sage euch: man muss noch Chaos in sich haben, um einen tanzenden Stern gebären zu können. Ich sage euch: ihr habt noch Chaos in euch."

	// Both parties generate long term ECDH keypairs, that are known to each
	// other via some out of band mechanism.
	csStaticAlice := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	staticAlice, _ := csStaticAlice.GenerateKeypair(rand.Reader)

	csStaticBob := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	staticBob, _ := csStaticBob.GenerateKeypair(rand.Reader)

	// Alice constructs a handshake state with both static keys.
	hsAlice, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   csStaticAlice,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeX,
		Initiator:     true,
		StaticKeypair: staticAlice,
		PeerStatic:    staticBob.Public,
	})

	// Build a BlockCiphertext via noise.
	msgAlice, _, _, err := hsAlice.WriteMessage(nil, []byte(plaintext))
	assert.NoError(err, "alice WriteMessage")
	assert.Equal(32+16+32+16+len(plaintext), len(msgAlice))

	// Alice sends msgAlice to Bob and is done.

	// Bob constructs a handshake state with his static key (one use).
	hsBob, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   csStaticBob,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeX,
		Initiator:     false,
		StaticKeypair: staticBob,
	})

	// Bob processes msgAlice all at once.
	msgBob, _, _, err := hsBob.ReadMessage(nil, msgAlice)
	assert.NoError(err, "hsBob.ReadMessage()")

	// Ta dah!
	//   msgBob: plaintext
	//   hsBob.PeerStatic(): aliceStatic.Public
	assert.Equal(staticAlice.Public, hsBob.PeerStatic(), "static key mismatch")
	assert.Equal([]byte(plaintext), msgBob, "plaintext mismatch")
}
