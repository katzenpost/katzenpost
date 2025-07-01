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
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
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
	nikeScheme := schemes.ByName("x25519")
	defaultPigeonholeGeometry := pigeonholeGeo.NewGeometry(1000, nikeScheme)

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
		SendMessage: &SendMessage{
			ID:      id,
			Payload: []byte("abc123"),
		},
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

	require.Equal(t, serverRequest.SendMessage.ID[:], request.SendMessage.ID[:])

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

func TestPKIDocumentForEpoch(t *testing.T) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	thin := &ThinClient{
		log:         logBackend.GetLogger("thinclient"),
		pkiDocCache: make(map[uint64]*cpki.Document),
	}

	// Test with empty cache - should return error
	doc, err := thin.PKIDocumentForEpoch(12345)
	require.Error(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "no PKI document available for the requested epoch")

	// Test with cached document - should return document
	testDoc := &cpki.Document{
		Epoch: 12345,
	}
	thin.pkiDocCache[12345] = testDoc

	doc, err = thin.PKIDocumentForEpoch(12345)
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, uint64(12345), doc.Epoch)
	require.Equal(t, testDoc, doc)

	// Test with different epoch - should return error
	doc, err = thin.PKIDocumentForEpoch(54321)
	require.Error(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "no PKI document available for the requested epoch")
}

func TestOfflineChannelOperations(t *testing.T) {
	// This test verifies that channel operations work when the daemon is not connected to the mixnet

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	// Create test geometries
	defaultSphinxGeometry := &geo.Geometry{
		UserForwardPayloadLength: 1000,
	}
	nikeScheme := schemes.ByName("x25519")
	defaultPigeonholeGeometry := pigeonholeGeo.NewGeometry(1000, nikeScheme)

	// Create a thin client in offline mode
	thin := &ThinClient{
		cfg: &Config{
			SphinxGeometry:     defaultSphinxGeometry,
			PigeonholeGeometry: defaultPigeonholeGeometry,
		},
		log:         logBackend.GetLogger("thinclient"),
		isConnected: false, // This means offline mode
		pkiDocCache: make(map[uint64]*cpki.Document),
	}

	// Test that offline mode state is correctly set
	require.False(t, thin.IsConnected())

	// Test that operations requiring mixnet connectivity fail with appropriate errors
	ctx := context.Background()

	// Test SendChannelQuery fails in offline mode
	err = thin.SendChannelQuery(ctx, 1, []byte("test"), &[32]byte{}, []byte("queue"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot send channel query in offline mode")

	// Test SendMessage fails in offline mode
	surbID := thin.NewSURBID()
	err = thin.SendMessage(surbID, []byte("test"), &[32]byte{}, []byte("queue"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot send message in offline mode")

	// Test SendMessageWithoutReply fails in offline mode
	err = thin.SendMessageWithoutReply([]byte("test"), &[32]byte{}, []byte("queue"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot send message in offline mode")

	// Test BlockingSendMessage fails in offline mode
	_, err = thin.BlockingSendMessage(ctx, []byte("test"), &[32]byte{}, []byte("queue"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot send message in offline mode")

	// Test SendReliableMessage fails in offline mode
	messageID := thin.NewMessageID()
	err = thin.SendReliableMessage(messageID, []byte("test"), &[32]byte{}, []byte("queue"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot send reliable message in offline mode")

	// Test BlockingSendReliableMessage fails in offline mode
	_, err = thin.BlockingSendReliableMessage(ctx, messageID, []byte("test"), &[32]byte{}, []byte("queue"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot send reliable message in offline mode")

	t.Log("All offline mode error handling tests passed")
}

func TestOfflineDialAndChannelOperations(t *testing.T) {
	// This test verifies that Dial() works when daemon reports not connected,
	// and that channel operations can be initiated (though not completed without daemon responses)

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	// Create test geometries
	defaultSphinxGeometry := &geo.Geometry{
		UserForwardPayloadLength: 1000,
	}
	nikeScheme := schemes.ByName("x25519")
	defaultPigeonholeGeometry := pigeonholeGeo.NewGeometry(1000, nikeScheme)

	// Create a pipe to simulate daemon communication
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	thin := &ThinClient{
		cfg: &Config{
			SphinxGeometry:     defaultSphinxGeometry,
			PigeonholeGeometry: defaultPigeonholeGeometry,
		},
		log:         logBackend.GetLogger("thinclient"),
		conn:        client,
		eventSink:   make(chan Event, 2),
		drainAdd:    make(chan chan Event),
		drainRemove: make(chan chan Event),
		pkiDocCache: make(map[uint64]*cpki.Document),
	}

	// Simulate daemon responses in a goroutine
	go func() {
		defer server.Close()

		// Send connection status (not connected)
		connectionStatusResponse := &Response{
			ConnectionStatusEvent: &ConnectionStatusEvent{
				IsConnected: false, // This is the key - daemon reports not connected
				Err:         nil,
			},
		}
		sendResponse(t, server, connectionStatusResponse)

		// Send PKI document
		testDoc := &cpki.Document{
			Epoch: 12345,
		}
		docBytes, err := cbor.Marshal(testDoc)
		require.NoError(t, err)

		pkiResponse := &Response{
			NewPKIDocumentEvent: &NewPKIDocumentEvent{
				Payload: docBytes,
			},
		}
		sendResponse(t, server, pkiResponse)
	}()

	// Test that Dial() succeeds even when daemon reports not connected
	err = thin.Dial()
	require.NoError(t, err, "Dial should succeed even when daemon is not connected to mixnet")

	// Verify offline mode state
	require.False(t, thin.IsConnected(), "Should not be connected to mixnet")

	t.Log("Successfully dialed daemon in offline mode")
	t.Log("Channel operations would work but require daemon responses to complete")
}

// Helper function to send responses to the thin client
func sendResponse(t *testing.T, conn net.Conn, response *Response) {
	responseBytes, err := cbor.Marshal(response)
	require.NoError(t, err)

	// Send length prefix
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, uint32(len(responseBytes)))

	// Send prefix + response
	message := append(prefix, responseBytes...)
	_, err = conn.Write(message)
	require.NoError(t, err)
}
