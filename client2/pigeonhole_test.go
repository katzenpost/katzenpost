// SPDX-FileCopyrightText: (c) 2026  David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client2

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/log"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/stretchr/testify/require"
)

func TestDaemonNewKeypair_Success(t *testing.T) {
	// Create a minimal daemon with required fields
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	port, err := getFreePort()
	require.NoError(t, err)
	cfg.ListenAddress = fmt.Sprintf("127.0.0.1:%d", port)

	client := &Client{cfg: cfg}
	rates := &Rates{}
	egressCh := make(chan *Request, 10)

	listener, err := NewListener(client, rates, egressCh, logBackend, nil)
	require.NoError(t, err)
	defer listener.Shutdown()

	d := &Daemon{
		logbackend:                logBackend,
		log:                       logBackend.GetLogger("test"),
		listener:                  listener,
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
	}

	// Generate a seed - just 32 random bytes
	seed := make([]byte, 32)
	_, err = rand.Reader.Read(seed)
	require.NoError(t, err)

	// Create a mock connection with a response channel
	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("test-app-newkeyp"))

	responseCh := make(chan *Response, 1)
	mockConn := &mockIncomingConn{
		appID:      testAppID,
		responseCh: responseCh,
	}

	// Register the mock connection
	listener.connsLock.Lock()
	listener.conns[*testAppID] = mockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	// Create the request
	request := &Request{
		AppID: testAppID,
		NewKeypair: &thin.NewKeypair{
			Seed: seed,
		},
	}

	// Call newKeypair
	d.newKeypair(request)

	// Check the response (with timeout to allow goroutine to process)
	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.NewKeypairReply)
		require.Equal(t, thin.ThinClientSuccess, resp.NewKeypairReply.ErrorCode)
		require.NotNil(t, resp.NewKeypairReply.WriteCap)
		require.NotNil(t, resp.NewKeypairReply.ReadCap)
	case <-time.After(time.Second):
		t.Fatal("Expected a response but got none within timeout")
	}
}

func TestDaemonNewKeypair_InvalidSeed(t *testing.T) {
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	port, err := getFreePort()
	require.NoError(t, err)
	cfg.ListenAddress = fmt.Sprintf("127.0.0.1:%d", port)

	client := &Client{cfg: cfg}
	rates := &Rates{}
	egressCh := make(chan *Request, 10)

	listener, err := NewListener(client, rates, egressCh, logBackend, nil)
	require.NoError(t, err)
	defer listener.Shutdown()

	d := &Daemon{
		logbackend:                logBackend,
		log:                       logBackend.GetLogger("test"),
		listener:                  listener,
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
	}

	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("test-app-invalid"))

	responseCh := make(chan *Response, 1)
	mockConn := &mockIncomingConn{
		appID:      testAppID,
		responseCh: responseCh,
	}

	listener.connsLock.Lock()
	listener.conns[*testAppID] = mockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	// Create request with invalid seed (too short)
	request := &Request{
		AppID: testAppID,
		NewKeypair: &thin.NewKeypair{
			Seed: []byte("invalid-seed-too-short"),
		},
	}

	d.newKeypair(request)

	select {
	case resp := <-responseCh:
		require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.NewKeypairReply.ErrorCode)
	case <-time.After(time.Second):
		t.Fatal("Expected a response but got none within timeout")
	}
}

// mockIncomingConn is a helper for testing that captures responses
type mockIncomingConn struct {
	appID      *[AppIDLength]byte
	responseCh chan *Response
}

func (m *mockIncomingConn) toIncomingConn(_ *listener, logBackend *log.Backend) *incomingConn {
	// Create a real incomingConn using net.Pipe
	clientConn, serverConn := net.Pipe()

	conn := &incomingConn{
		log:   logBackend.GetLogger("mock-conn"),
		conn:  serverConn,
		appID: m.appID,
	}

	// Start a goroutine to read responses and forward them
	go func() {
		defer clientConn.Close()
		for {
			// Read length prefix (4 bytes, big-endian)
			lenPrefix := make([]byte, 4)
			_, err := io.ReadFull(clientConn, lenPrefix)
			if err != nil {
				return
			}
			// Read the response blob
			blobLen := binary.BigEndian.Uint32(lenPrefix)
			blob := make([]byte, blobLen)
			_, err = io.ReadFull(clientConn, blob)
			if err != nil {
				return
			}
			// Decode the CBOR response (it's a thin.Response)
			thinResp := &thin.Response{}
			if err := cbor.Unmarshal(blob, thinResp); err != nil {
				return
			}
			// Convert to Response and forward to channel
			resp := &Response{
				AppID:           m.appID,
				NewKeypairReply: thinResp.NewKeypairReply,
			}
			m.responseCh <- resp
		}
	}()

	return conn
}
