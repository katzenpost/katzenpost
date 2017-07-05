// common_test.go - Tests for common code of the noise based wire protocol.
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

package common

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/katzenpost/noise"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestCommandNoOp(t *testing.T) {
	assert := assert.New(t)
	var err error
	var cmd1, cmd2 Command
	cmd1 = NoOpCommand{}
	raw1 := cmd1.toBytes()
	cmd2, err = fromBytes(raw1)
	assert.NoError(err, "fromBytes unexpectedly failed")
	raw2 := cmd2.toBytes()
	assert.Equal(raw1, raw2, "serialized commands not equal")
}

func TestCommandDisconnect(t *testing.T) {
	assert := assert.New(t)
	var err error
	var cmd1, cmd2 Command
	cmd1 = DisconnectCommand{}
	raw1 := cmd1.toBytes()
	cmd2, err = fromBytes(raw1)
	assert.NoError(err, "fromBytes unexpectedly failed")
	raw2 := cmd2.toBytes()
	assert.Equal(raw1, raw2, "serialized commands not equal")
}

func TestCommandAuthenticate(t *testing.T) {
	assert := assert.New(t)
	var err error
	var cmd1, cmd2 Command
	cmd1 = AuthenticateCommand{}
	raw1 := cmd1.toBytes()
	cmd2, err = fromBytes(raw1)
	assert.NoError(err, "fromBytes unexpectedly failed")
	raw2 := cmd2.toBytes()
	assert.Equal(raw1, raw2, "serialized commands not equal")
}

func TestCommandSendPacket(t *testing.T) {
	assert := assert.New(t)
	var err error
	var cmd1, cmd2 Command
	cmd1 = SendPacketCommand{}
	raw1 := cmd1.toBytes()
	cmd2, err = fromBytes(raw1)
	assert.NoError(err, "fromBytes unexpectedly failed")
	raw2 := cmd2.toBytes()
	assert.Equal(raw1, raw2, "serialized commands not equal")
}

func TestCommandMessageMessage(t *testing.T) {
	assert := assert.New(t)
	var err error
	var cmd2 Command
	message := MessageMessageCommand{
		QueueSizeHint: uint8(1),
		Sequence:      uint32(666),
	}
	count, err := rand.Read(message.EncryptedPayload[:])
	assert.Equal(count, messagePayloadSize, "not equal")
	raw1 := message.toBytes()
	cmd2, err = fromBytes(raw1)

	cmd, ok := cmd2.(MessageMessageCommand)
	assert.True(ok, "ok should be True")
	assert.Equal(message.Sequence, cmd.Sequence, "Sequences should be equal")

	assert.NoError(err, "fromBytes unexpectedly failed")
	raw2 := cmd2.toBytes()
	assert.Equal(raw1, raw2, "serialized commands not equal")
}

func TestEncryptDecrypt(t *testing.T) {
	assert := assert.New(t)

	clientStaticKeypair := noise.DH25519.GenerateKeypair(rand.Reader)
	clientConfig := noise.Config{}
	clientConfig.CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	clientConfig.Random = rand.Reader
	clientConfig.Pattern = noise.HandshakeNN
	clientConfig.Initiator = true
	clientConfig.Prologue = []byte{0}
	clientConfig.StaticKeypair = clientStaticKeypair
	clientConfig.EphemeralKeypair = noise.DH25519.GenerateKeypair(rand.Reader)
	clientHs := noise.NewHandshakeState(clientConfig)

	serverStaticKeypair := noise.DH25519.GenerateKeypair(rand.Reader)
	serverConfig := noise.Config{}
	serverConfig.CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	serverConfig.Random = rand.Reader
	serverConfig.Pattern = noise.HandshakeNN
	serverConfig.Initiator = false
	serverConfig.Prologue = []byte{0}
	serverConfig.StaticKeypair = serverStaticKeypair
	serverConfig.EphemeralKeypair = noise.DH25519.GenerateKeypair(rand.Reader)
	serverHs := noise.NewHandshakeState(serverConfig)

	clientHsMsg, _, _ := clientHs.WriteMessage(nil, nil)
	assert.Equal(32, len(clientHsMsg), "client handshake message is unexpected size")

	serverHsResult, _, _, err := serverHs.ReadMessage(nil, clientHsMsg)
	assert.NoError(err, "server failed to read client handshake message")
	assert.Equal(0, len(serverHsResult), "server result message is unexpected size")

	serverHsMsg, csR0, csR1 := serverHs.WriteMessage(nil, nil)
	assert.Equal(48, len(serverHsMsg), "server handshake message is unexpected size")

	clientHsResult, csI0, csI1, err := clientHs.ReadMessage(nil, serverHsMsg)
	assert.NoError(err, "client failed to read server handshake message")
	assert.Equal(0, len(clientHsResult), "client result message is unexpected size")

	cmd1 := MessageMessageCommand{
		QueueSizeHint: uint8(1),
		Sequence:      uint32(666),
	}
	count, err := rand.Read(cmd1.EncryptedPayload[:])
	assert.Equal(count, len(cmd1.EncryptedPayload))
	assert.NoError(err, "unexpected error")

	ciphertext := CommandToCiphertextBytes(csR0, cmd1)
	raw1 := cmd1.toBytes()

	cmd2, err := FromCiphertextBytes(csI0, ciphertext)
	assert.NoError(err, "FromCiphertextBytes failed")

	cmd, _ := cmd2.(MessageMessageCommand)
	assert.Equal(cmd.Sequence, cmd1.Sequence, "MessageMessage Command Sequence fields should be equal")

	raw2 := cmd2.toBytes()
	assert.Equal(raw1, raw2, "byte slices should be equal")

	ciphertext = CommandToCiphertextBytes(csI1, cmd1)
	raw1 = cmd1.toBytes()

	cmd2, err = FromCiphertextBytes(csR1, ciphertext)
	assert.NoError(err, "FromCiphertextBytes failed")
	raw2 = cmd2.toBytes()

	assert.Equal(raw1, raw2, "byte slices should be equal")
}

func TestSessionBasic(t *testing.T) {
	assert := assert.New(t)

	clientPublicKey, clientPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(err, "failed to gen key")
	serverPublicKey, serverPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(err, "failed to gen key")

	clientConfig := Config{
		Identifier:                []byte("client1"),
		LongtermEd25519PublicKey:  clientPublicKey,
		LongtermEd25519PrivateKey: clientPrivateKey,
		Initiator:                 true,
		Random:                    rand.Reader,
	}
	clientSession := New(&clientConfig, nil)

	serverConfig := Config{
		Identifier:                []byte("NSA_MIX_101"),
		LongtermEd25519PublicKey:  serverPublicKey,
		LongtermEd25519PrivateKey: serverPrivateKey,
		Initiator:                 false,
		Random:                    rand.Reader,
	}
	serverSession := New(&serverConfig, nil)
	done := serverSession.NotifyClosed()

	clientConn, serverConn := net.Pipe()

	go func() {
		err := serverSession.Initiate(serverConn)
		assert.NoError(err, "server failed to initiate session")

		cmd, err := serverSession.Receive()
		assert.NoError(err, "server failed to receive session command")

		_, ok := cmd.(DisconnectCommand)
		assert.True(ok, "type assertion should be true")

		err = serverSession.Close()
		assert.NoError(err, "server failed to close session")
	}()
	go func() {
		err := clientSession.Initiate(clientConn)
		assert.NoError(err, "client failed to initiate session")

		err = clientSession.Send(DisconnectCommand{})
		assert.NoError(err, "client failed to disconnect session")

		err = clientSession.Close()
		assert.NoError(err, "client failed to close session")
	}()
	<-done
}
