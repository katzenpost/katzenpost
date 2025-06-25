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

	// test WriteChannel

	pigeonholeGeometry := pigeonholeGeo.NewGeometry(50, nikeScheme)

	thin.cfg = &Config{
		SphinxGeometry:     defaultSphinxGeometry,
		PigeonholeGeometry: pigeonholeGeometry,
	}

	channelID := &[ChannelIDLength]byte{}
	_, err = rand.Reader.Read(channelID[:])
	require.NoError(t, err)

	ctx := context.Background()

	largePayload := make([]byte, 100)
	err = thin.OldWriteChannel(ctx, channelID, largePayload)
	require.Error(t, err)
	require.Contains(t, err.Error(), "payload size")
	require.Contains(t, err.Error(), "exceeds maximum allowed size")

	err = thin.OldWriteChannel(ctx, nil, largePayload)
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
		SendMessage: &SendMessage{
			Payload: largeSphinxPayload,
		},
	}
	err = thin.writeMessage(request)
	require.Error(t, err)
	require.Contains(t, err.Error(), "payload size")
	require.Contains(t, err.Error(), "exceeds maximum allowed size")
}

func TestCopyChannelValidation(t *testing.T) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	client, _ := net.Pipe()
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

	ctx := context.Background()

	// Test with nil channelID
	err = thin.OldCopyChannel(ctx, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "channelID cannot be nil")

	// Test with nil context
	channelID := &[ChannelIDLength]byte{}
	_, err = rand.Reader.Read(channelID[:])
	require.NoError(t, err)

	err = thin.OldCopyChannel(nil, channelID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "context cannot be nil")
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
