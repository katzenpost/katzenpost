// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	"github.com/stretchr/testify/require"
)

func TestThinTCPSendRecv(t *testing.T) {

	// test writeMessage

	const messagePrefixLen = 4

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	client, server := net.Pipe()
	defaultSphinxGeometry := &geo.Geometry{
		UserForwardPayloadLength: 1000,
	}
	defaultPigeonholeGeometry := &replicaCommon.Geometry{
		BoxPayloadLength: 1000,
	}

	thin := ThinClient{
		cfg: &Config{
			SphinxGeometry:     defaultSphinxGeometry,
			PigeonholeGeometry: defaultPigeonholeGeometry,
		},
		log:   logBackend.GetLogger("thinclient"),
		isTCP: true,
		conn:  client,
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

	// test WriteChannel

	pigeonholeGeometry := &replicaCommon.Geometry{
		BoxPayloadLength: 50,
	}

	thin.cfg = &Config{
		SphinxGeometry:     defaultSphinxGeometry,
		PigeonholeGeometry: pigeonholeGeometry,
	}

	channelID := &[ChannelIDLength]byte{}
	_, err = rand.Reader.Read(channelID[:])
	require.NoError(t, err)

	ctx := context.Background()

	largePayload := make([]byte, 100)
	err = thin.WriteChannel(ctx, channelID, largePayload)
	require.Error(t, err)
	require.Contains(t, err.Error(), "payload size")
	require.Contains(t, err.Error(), "exceeds maximum allowed size")

	err = thin.WriteChannel(ctx, nil, largePayload)
	require.Error(t, err)
	require.Contains(t, err.Error(), "channelID cannot be nil")

	sphinxGeometry := &geo.Geometry{
		UserForwardPayloadLength: 30,
	}
	thin.cfg = &Config{
		SphinxGeometry:     sphinxGeometry,
		PigeonholeGeometry: defaultPigeonholeGeometry,
	}

	largeSphinxPayload := make([]byte, 50)
	request = &Request{
		Payload: largeSphinxPayload,
	}
	err = thin.writeMessage(request)
	require.Error(t, err)
	require.Contains(t, err.Error(), "payload size")
	require.Contains(t, err.Error(), "exceeds maximum allowed size")
}
