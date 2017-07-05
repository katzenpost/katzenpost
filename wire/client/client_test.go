// client_test.go - Noise based wire protocol client tests.
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

package client

import (
	"crypto/rand"
	"fmt"
	"net"
	"testing"

	"github.com/katzenpost/core/wire/common"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

func TestClientSendReceiveMessage(t *testing.T) {
	assert := assert.New(t)

	// generate Alice and Bob's wire protocol Ed25519 keys for
	// authenticating themselves to "the server"
	aliceEd25519PublicKey, aliceEd25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(err, "failed to gen key")
	bobEd25519PublicKey, bobEd25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(err, "failed to gen key")

	// create Alice and Bob's Session
	aliceConfig := common.Config{
		Identifier:                []byte("alice"),
		LongtermEd25519PublicKey:  aliceEd25519PublicKey,
		LongtermEd25519PrivateKey: aliceEd25519PrivateKey,
		Initiator:                 true,
		Random:                    rand.Reader,
	}
	aliceSession := common.New(&aliceConfig, nil)
	//aliceDone := aliceSession.NotifyClosed()

	bobConfig := common.Config{
		Identifier:                []byte("bob"),
		LongtermEd25519PublicKey:  bobEd25519PublicKey,
		LongtermEd25519PrivateKey: bobEd25519PrivateKey,
		Initiator:                 true,
		Random:                    rand.Reader,
	}
	bobSession := common.New(&bobConfig, nil)
	bobDone := bobSession.NotifyClosed()

	// create "message Provider" server sessions
	serverEd25519PublicKey, serverEd25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(err, "failed to gen key")
	serverConfig := common.Config{
		Identifier:                []byte("Provider_123"),
		LongtermEd25519PublicKey:  serverEd25519PublicKey,
		LongtermEd25519PrivateKey: serverEd25519PrivateKey,
		Initiator:                 false,
		Random:                    rand.Reader,
	}
	serverSession1 := common.New(&serverConfig, nil)
	serverSession2 := common.New(&serverConfig, nil)

	//serverDone := serverSession.NotifyClosed()

	aliceConn, serverConn1 := net.Pipe()
	bobConn, serverConn2 := net.Pipe()

	// server
	go func() {
		err := serverSession1.Initiate(serverConn1)
		assert.NoError(err, "server failed to initiate session")

		cmd, err := serverSession1.Receive()
		assert.NoError(err, "server failed to receive session command")

		cmd2, ok := cmd.(common.MessageMessageCommand)
		assert.True(ok, "type assertion should be true")

		cmd, err = serverSession1.Receive()
		assert.NoError(err, "server failed to receive session command")
		_, ok = cmd.(common.DisconnectCommand)
		assert.True(ok, "type assertion should be true")

		err = serverSession1.Close()
		assert.NoError(err, "server failed to close session")

		err = serverSession2.Initiate(serverConn2)
		assert.NoError(err, "server failed to initiate session")

		cmd, err = serverSession2.Receive()
		assert.NoError(err, "server failed to receive session command")

		_, ok = cmd.(common.RetrieveMessageCommand)
		assert.True(ok, "type assertion should be true")

		err = serverSession2.Send(cmd2)
		assert.NoError(err, "server failed to send message to client")

		cmd, err = serverSession2.Receive()
		assert.NoError(err, "server failed to receive session command")

		_, ok = cmd.(common.DisconnectCommand)
		assert.True(ok, "type assertion should be true")

		err = serverSession2.Close()
		assert.NoError(err, "server failed to close session")
	}()

	go func() {
		// Alice encrypt message to Bob and sends it to the server
		err := aliceSession.Initiate(aliceConn)
		assert.NoError(err, "Alice failed to initiate session")

		cmd := common.MessageMessageCommand{
			QueueSizeHint: uint8(1),
			Sequence:      uint32(123),
		}
		err = aliceSession.Send(cmd)
		assert.NoError(err, "Alice failed to send")

		err = aliceSession.Send(common.DisconnectCommand{})
		assert.NoError(err, "Alice failed to disconnect session")

		err = aliceSession.Close()
		assert.NoError(err, "Alice failed to close session")

		//<-aliceDone

		err = bobSession.Initiate(bobConn)
		assert.NoError(err, "Bob failed to initiate session")

		err = bobSession.Send(common.RetrieveMessageCommand{})
		assert.NoError(err, "Bob failed to disconnect session")

		cmd1, err := bobSession.Receive()
		assert.NoError(err, "Bob failed to recieve session command")

		switch v := cmd1.(type) {
		case common.MessageMessageCommand:
			fmt.Println("messageMessage command type", v)
		default:
			fmt.Println("unknown command type", v)
		}
		_, ok := cmd1.(common.MessageMessageCommand)
		assert.True(ok, "type assertion should be true")

		err = bobSession.Send(common.DisconnectCommand{})
		assert.NoError(err, "Bob failed to disconnect session")

		err = bobSession.Close()
		assert.NoError(err, "Bob failed to close session")
	}()

	<-bobDone
}
