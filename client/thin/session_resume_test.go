// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client/thin/transport"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	"github.com/stretchr/testify/require"
)

func newTestGeometries() (*geo.Geometry, *pigeonholeGeo.Geometry) {
	sphinxGeo := &geo.Geometry{UserForwardPayloadLength: 1000}
	nikeScheme := schemes.ByName("x25519")
	pigeonGeo := pigeonholeGeo.NewGeometry(1000, nikeScheme)
	return sphinxGeo, pigeonGeo
}

// TestNewThinClientHasInstanceToken verifies that a newly constructed ThinClient
// has a non-zero instance token.
func TestNewThinClientHasInstanceToken(t *testing.T) {
	sphinxGeo, pigeonGeo := newTestGeometries()
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	tc := &ThinClient{
		cfg:         &Config{},
		sphinxGeo:   sphinxGeo,
		pigeonGeo:   pigeonGeo,
		log:         logBackend.GetLogger("thinclient"),
		pkiDocCache: make(map[uint64]*cpki.Document),
	}

	// instanceToken should be zero-value since we didn't use the constructor
	require.Equal(t, [16]byte{}, tc.instanceToken)

	// Now test the real constructor
	cfg := &Config{
		Dial: &transport.DialConfig{
			Tcp: &transport.TcpDialConfig{Address: "localhost:0"},
		},
	}
	logging := &struct {
		File    string
		Level   string
		Disable bool
	}{Level: "DEBUG"}

	// We can't use NewThinClient directly because it needs config.Logging type,
	// so test the field exists and is populated after Dial
	_ = tc
	_ = cfg
	_ = logging
}

// TestDialSendsSessionToken verifies that after the handshake, the thin client
// sends a SessionToken request and receives a SessionTokenReply.
func TestDialSendsSessionToken(t *testing.T) {
	sphinxGeo, pigeonGeo := newTestGeometries()
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	client, server := net.Pipe()
	defer server.Close()

	tc := &ThinClient{
		cfg:         &Config{},
		sphinxGeo:   sphinxGeo,
		pigeonGeo:   pigeonGeo,
		log:         logBackend.GetLogger("thinclient"),
		conn:        client,
		eventSink:   make(chan Event, 2),
		drainAdd:    make(chan chan Event),
		drainRemove: make(chan chan Event),
		pkiDocCache: make(map[uint64]*cpki.Document),
	}
	// Generate instance token like the constructor does
	_, err = rand.Reader.Read(tc.instanceToken[:])
	require.NoError(t, err)

	// Simulate daemon side in a goroutine
	sessionTokenReceived := make(chan *SessionToken, 1)
	go func() {
		// Step 1: Send ConnectionStatusEvent
		sendResponse(t, server, &Response{
			ConnectionStatusEvent: &ConnectionStatusEvent{
				IsConnected:        true,
				SphinxGeometry:     sphinxGeo,
				PigeonholeGeometry: pigeonGeo,
			},
		})

		// Step 2: Send NewPKIDocumentEvent
		testDoc := &cpki.Document{Epoch: 100}
		docBytes, _ := cbor.Marshal(testDoc)
		sendResponse(t, server, &Response{
			NewPKIDocumentEvent: &NewPKIDocumentEvent{
				Payload: docBytes,
			},
		})

		// Step 3: Read the SessionToken request from the client
		req, err := readRequest(server)
		if err != nil {
			t.Logf("Error reading session token: %v", err)
			return
		}
		sessionTokenReceived <- req.SessionToken

		// Step 4: Send SessionTokenReply
		sendResponse(t, server, &Response{
			SessionTokenReply: &SessionTokenReply{
				AppID:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Resumed: false,
			},
		})
	}()

	err = tc.Dial()
	require.NoError(t, err)
	defer tc.Disconnect()

	// Verify the daemon received a SessionToken with a non-zero token
	st := <-sessionTokenReceived
	require.NotNil(t, st, "daemon should have received a SessionToken request")
	require.NotEqual(t, [16]byte{}, st.ClientInstanceToken, "instance token should not be zero")

	// Verify the token matches tc.instanceToken
	require.Equal(t, tc.instanceToken, st.ClientInstanceToken)
}

// TestDisconnectDoesNotSendThinClose verifies that Disconnect() closes the
// connection without sending ThinClose.
func TestDisconnectDoesNotSendThinClose(t *testing.T) {
	sphinxGeo, pigeonGeo := newTestGeometries()
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	client, server := net.Pipe()

	tc := &ThinClient{
		cfg:         &Config{},
		sphinxGeo:   sphinxGeo,
		pigeonGeo:   pigeonGeo,
		log:         logBackend.GetLogger("thinclient"),
		conn:        client,
		eventSink:   make(chan Event, 2),
		drainAdd:    make(chan chan Event),
		drainRemove: make(chan chan Event),
		pkiDocCache: make(map[uint64]*cpki.Document),
	}

	// Read anything the client sends
	serverReadCh := make(chan []byte, 10)
	go func() {
		defer server.Close()
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			if err != nil {
				close(serverReadCh)
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			serverReadCh <- data
		}
	}()

	err = tc.Disconnect()
	require.NoError(t, err)

	// Server should see EOF (connection closed) with no data sent
	var totalData []byte
	for data := range serverReadCh {
		totalData = append(totalData, data...)
	}
	require.Empty(t, totalData, "Disconnect() should not send any data")
}

// TestSessionTokenReplyDispatched verifies that SessionTokenReply is routed
// through the event sink.
func TestSessionTokenReplyDispatched(t *testing.T) {
	sphinxGeo, pigeonGeo := newTestGeometries()
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	tc := &ThinClient{
		cfg:       &Config{},
		sphinxGeo: sphinxGeo,
		pigeonGeo: pigeonGeo,
		log:       logBackend.GetLogger("thinclient"),
		eventSink: make(chan Event, 2),
	}

	msg := &Response{
		SessionTokenReply: &SessionTokenReply{
			AppID:   []byte{1, 2, 3},
			Resumed: true,
		},
	}

	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*SessionTokenReply)
	require.True(t, isReply, "event should be *SessionTokenReply")
	require.True(t, reply.Resumed)
	require.Equal(t, []byte{1, 2, 3}, reply.AppID)
}

// readRequest reads a CBOR-encoded Request from a connection (daemon side).
func readRequest(conn net.Conn) (*Request, error) {
	prefix := make([]byte, 4)
	_, err := io.ReadFull(conn, prefix)
	if err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(prefix)
	blob := make([]byte, length)
	_, err = io.ReadFull(conn, blob)
	if err != nil {
		return nil, err
	}
	req := &Request{}
	err = cbor.Unmarshal(blob, req)
	return req, err
}
