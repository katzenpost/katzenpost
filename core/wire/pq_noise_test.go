// Copyright (C) 2019, 2021 Yawning Angel. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package wire

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/yawning/nyquist.git"
	"gitlab.com/yawning/nyquist.git/cipher"
	"gitlab.com/yawning/nyquist.git/hash"
	"gitlab.com/yawning/nyquist.git/kem"
	"gitlab.com/yawning/nyquist.git/pattern"
	"gitlab.com/yawning/nyquist.git/seec"
)

func TestNyquistPqNoiseParams1(t *testing.T) {
	ErrDone := errors.New("nyquist: handshake complete")
	protocol, err := nyquist.NewProtocol("Noise_pqXX_Kyber1024_ChaChaPoly_BLAKE2s")
	require.NoError(t, err)

	seecGenRand, err := seec.GenKeyPRPAES(rand.Reader, 256)
	require.NoError(t, err, "seec.GenKeyPRPAES")

	// Protocols can also be constructed manually.
	protocol2 := &nyquist.Protocol{
		Pattern: pattern.PqXX,
		KEM:     kem.Kyber1024,
		Cipher:  cipher.ChaChaPoly,
		Hash:    hash.BLAKE2s,
	}
	require.Equal(t, protocol, protocol2)

	// Each side needs a HandshakeConfig, properly filled out.
	aliceStatic, err := protocol.KEM.GenerateKeypair(seecGenRand)
	require.NoError(t, err, "Generate Alice's static keypair")
	aliceCfg := &nyquist.HandshakeConfig{
		Protocol: protocol,
		KEM: &nyquist.KEMConfig{
			LocalStatic: aliceStatic,
			GenKey:      seec.GenKeyPRPAES,
		},
		IsInitiator: true,
	}

	bobStatic, err := protocol.KEM.GenerateKeypair(seecGenRand)
	require.NoError(t, err, "Generate Bob's static keypair")
	bobCfg := &nyquist.HandshakeConfig{
		Protocol: protocol,
		KEM: &nyquist.KEMConfig{
			LocalStatic: bobStatic,
		},
		// SEECGenKey is optional, and just using the raw entropy
		// device is supported.
		IsInitiator: false,
	}

	// Each side then constructs a HandshakeState.
	aliceHs, err := nyquist.NewHandshake(aliceCfg)
	require.NoError(t, err, "NewHandshake(aliceCfg)")

	bobHs, err := nyquist.NewHandshake(bobCfg)
	require.NoError(t, err, "NewHandshake(bobCfg")

	// Ensuring that HandshakeState.Reset() is called, will make sure that
	// the HandshakeState isn't inadvertently reused.
	defer aliceHs.Reset()
	defer bobHs.Reset()

	// The SymmetricState and CipherState objects embedded in the
	// HandshakeState can be accessed while the handshake is in progress,
	// though most users likely will not need to do this.
	aliceSs := aliceHs.SymmetricState()
	require.NotNil(t, aliceSs, "aliceHs.SymmetricState()")
	aliceCs := aliceSs.CipherState()
	require.NotNil(t, aliceCs, "aliceSS.CipherState()")

	// Then, each side calls hs.ReadMessage/hs.WriteMessage as appropriate.
	alicePlaintextE := []byte("alice e plaintext") // Handshake message payloads are optional.
	aliceMsg1, err := aliceHs.WriteMessage(nil, alicePlaintextE)
	require.NoError(t, err, "aliceHs.WriteMessage(1)") // (alice) -> e

	bobRecv, err := bobHs.ReadMessage(nil, aliceMsg1)
	require.NoError(t, err, "bobHs.ReadMessage(alice1)")
	require.Equal(t, bobRecv, alicePlaintextE)

	bobMsg1, err := bobHs.WriteMessage(nil, nil) // (bob) -> ekem, s
	require.NoError(t, err, "bobHS.WriteMessage(bob1)")

	_, err = aliceHs.ReadMessage(nil, bobMsg1)
	require.NoError(t, err, "aliceHS.ReadMessage(bob1)")

	aliceMsg2, err := aliceHs.WriteMessage(nil, nil) // (alice) -> skem, s
	require.NoError(t, err, "aliceHs.WriteMessage(alice2)")

	_, err = bobHs.ReadMessage(nil, aliceMsg2)
	require.NoError(t, err, "bobHs.ReadMessage(alice2)")

	bobMsg2, err := bobHs.WriteMessage(nil, nil) // (bob) -> skem
	require.Equal(t, ErrDone, err, "bobHs.WriteMessage(bob2)")

	_, err = aliceHs.ReadMessage(nil, bobMsg2)
	require.Equal(t, ErrDone, err, "aliceHs.ReadMessage(bob2)")

	// Once a handshake is completed, the CipherState objects, handshake hash
	// and various public keys can be pulled out of the HandshakeStatus object.
	aliceStatus := aliceHs.GetStatus()
	bobStatus := bobHs.GetStatus()

	require.Equal(t, aliceStatus.HandshakeHash, bobStatus.HandshakeHash, "Handshake hashes match")
	require.Equal(t, aliceStatus.KEM.LocalEphemeral.Bytes(), bobStatus.KEM.RemoteEphemeral.Bytes())
	require.Equal(t, aliceStatus.KEM.RemoteStatic.Bytes(), bobStatic.Public().Bytes())
	require.Equal(t, bobStatus.KEM.RemoteStatic.Bytes(), aliceStatic.Public().Bytes())
	// Note: Unlike in normal XX, bob does not generate `e`.
	require.Nil(t, aliceStatus.KEM.RemoteEphemeral)
	require.Nil(t, bobStatus.KEM.LocalEphemeral)

	// Then the CipherState objects can be used to exchange messages.
	aliceTx, aliceRx := aliceStatus.CipherStates[0], aliceStatus.CipherStates[1]
	bobRx, bobTx := bobStatus.CipherStates[0], bobStatus.CipherStates[1] // Reversed from alice!

	// Naturally CipherState.Reset() also exists.
	defer func() {
		aliceTx.Reset()
		aliceRx.Reset()
	}()
	defer func() {
		bobTx.Reset()
		bobRx.Reset()
	}()

	// Alice -> Bob, post-handshake.
	alicePlaintext := []byte("alice transport plaintext")
	aliceMsg3, err := aliceTx.EncryptWithAd(nil, nil, alicePlaintext)
	require.NoError(t, err, "aliceTx.EncryptWithAd()")

	bobRecv, err = bobRx.DecryptWithAd(nil, nil, aliceMsg3)
	require.NoError(t, err, "bobRx.DecryptWithAd()")
	require.Equal(t, alicePlaintext, bobRecv)

	// Bob -> Alice, post-handshake.
	bobPlaintext := []byte("bob transport plaintext")
	bobMsg3, err := bobTx.EncryptWithAd(nil, nil, bobPlaintext)
	require.NoError(t, err, "bobTx.EncryptWithAd()")

	aliceRecv, err := aliceRx.DecryptWithAd(nil, nil, bobMsg3)
	require.NoError(t, err, "aliceRx.DecryptWithAd")
	require.Equal(t, bobPlaintext, aliceRecv)
}
