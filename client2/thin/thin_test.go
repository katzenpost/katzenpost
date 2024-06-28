// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/rand"
	"github.com/stretchr/testify/require"
)

func TestThinTCPSendRecv(t *testing.T) {
	const messagePrefixLen = 4

	client, server := net.Pipe()
	thin := ThinClient{
		isTCP: true,
		conn:  client,
	}

	id := &[MessageIDLength]byte{}
	_, err := rand.Reader.Read(id[:])
	require.NoError(t, err)

	request := &Request{
		ID:      id,
		Payload: []byte("abc123"),
	}
	go thin.writeMessage(request)

	prefix := make([]byte, messagePrefixLen)
	_, err = io.ReadFull(server, prefix)
	require.NoError(t, err)

	prefixLen := binary.BigEndian.Uint32(prefix)

	message := make([]byte, prefixLen)
	_, err = io.ReadFull(server, message)
	require.NoError(t, err)

	serverRequest := new(Request)
	err = cbor.Unmarshal(message, serverRequest)
	require.NoError(t, err)

	require.Equal(t, serverRequest.ID[:], request.ID[:])

	sem1 := make(chan bool)
	response := new(Response)
	go func() {
		response, err = thin.readMessage()
		require.NoError(t, err)
		sem1 <- true
	}()

	serverResponse := &Response{
		ConnectionStatusEvent: &ConnectionStatusEvent{
			IsConnected: true,
			Err:         nil,
		},
	}
	serverMessage, err := cbor.Marshal(serverResponse)
	require.NoError(t, err)

	prefixLen = uint32(len(serverMessage))
	prefix = make([]byte, messagePrefixLen)
	binary.BigEndian.PutUint32(prefix[:], prefixLen)

	serverMessage = append(prefix, serverMessage...)

	_, err = server.Write(serverMessage)
	require.NoError(t, err)

	<-sem1
	require.Equal(t, response.ConnectionStatusEvent.IsConnected, true)
	require.Equal(t, serverResponse.ConnectionStatusEvent.IsConnected, true)
}
