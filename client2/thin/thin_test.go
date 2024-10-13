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
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/stretchr/testify/require"
)

func TestThinTCPSendRecv(t *testing.T) {

	// test writeMessage

	const messagePrefixLen = 4

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	client, server := net.Pipe()
	thin := ThinClient{
		log:  logBackend.GetLogger("thinclient"),
		conn: client,
	}

	id := &[MessageIDLength]byte{}
	_, err = rand.Reader.Read(id[:])
	require.NoError(t, err)

	request := &Request{
		ID:      id,
		Payload: []byte("abc123"),
	}
	thinWriteMessageErrCh := make(chan error, 0)
	go func() {
		thinWriteMessageErrCh <- thin.writeMessage(request)
	}()

	prefix := make([]byte, messagePrefixLen)
	_, err = io.ReadFull(server, prefix)
	require.NoError(t, err)

	prefixLen := binary.BigEndian.Uint32(prefix)

	message := make([]byte, prefixLen)
	_, err = io.ReadFull(server, message)
	require.NoError(t, err)

	// verify thin writeMessage didn't return error
	e := <-thinWriteMessageErrCh
	require.NoError(t, e)

	serverRequest := new(Request)
	err = cbor.Unmarshal(message, serverRequest)
	require.NoError(t, err)

	require.Equal(t, serverRequest.ID[:], request.ID[:])

	// test readMessage

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

	serverWriteMessageErrCh := make(chan error, 0)
	go func() {
		_, err := server.Write(serverMessage)
		serverWriteMessageErrCh <- err
	}()

	response := new(Response)
	response, err = thin.readMessage()
	require.NoError(t, err)

	require.Equal(t, response.ConnectionStatusEvent.IsConnected, true)
	require.Equal(t, serverResponse.ConnectionStatusEvent.IsConnected, true)

	e = <-serverWriteMessageErrCh
	require.NoError(t, e)
}
