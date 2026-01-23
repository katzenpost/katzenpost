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
	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
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

	// Check to make sure the write and read caps work, here:

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
				AppID:             m.appID,
				NewKeypairReply:   thinResp.NewKeypairReply,
				EncryptReadReply:  thinResp.EncryptReadReply,
				EncryptWriteReply: thinResp.EncryptWriteReply,
			}
			m.responseCh <- resp
		}
	}()

	return conn
}

// createMockPKIDocument creates a minimal PKI document with 2 replica descriptors
// for use in testing encryptRead.
func createMockPKIDocument(t *testing.T) *cpki.Document {
	currentEpoch, _, _ := epochtime.Now()
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	// Create 2 replica descriptors with envelope keys
	replicaDescriptors := make([]*cpki.ReplicaDescriptor, 2)
	for i := 0; i < 2; i++ {
		// Generate a NIKE key pair for each replica
		pubKey, _, err := replicaCommon.NikeScheme.GenerateKeyPair()
		require.NoError(t, err)
		pubKeyBytes, err := pubKey.MarshalBinary()
		require.NoError(t, err)

		// Create identity key (just random bytes for testing)
		identityKey := make([]byte, 32)
		_, err = rand.Reader.Read(identityKey)
		require.NoError(t, err)

		replicaDescriptors[i] = &cpki.ReplicaDescriptor{
			Name:        fmt.Sprintf("replica-%d", i),
			IdentityKey: identityKey,
			EnvelopeKeys: map[uint64][]byte{
				replicaEpoch: pubKeyBytes,
			},
		}
	}

	return &cpki.Document{
		Epoch:           currentEpoch,
		StorageReplicas: replicaDescriptors,
	}
}

func TestDaemonEncryptRead_Success(t *testing.T) {
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

	// Create a mock PKI document and store it in the client
	doc := createMockPKIDocument(t)
	currentEpoch, _, _ := epochtime.Now()
	client.pki = &pki{
		c:    client,
		docs: sync.Map{},
	}
	client.pki.docs.Store(currentEpoch, &CachedDoc{
		Doc:  doc,
		Blob: nil,
	})

	d := &Daemon{
		logbackend:                logBackend,
		log:                       logBackend.GetLogger("test"),
		listener:                  listener,
		client:                    client,
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
	}

	// Create a WriteCap and ReadCap for testing
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	readCap := writeCap.ReadCap()

	// Create a StatefulWriter to get a valid MessageBoxIndex
	statefulWriter, err := bacap.NewStatefulWriter(writeCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	messageBoxIndex := statefulWriter.GetCurrentMessageIndex()

	// Set up mock connection
	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("test-encryptread"))

	responseCh := make(chan *Response, 1)
	mockConn := &mockIncomingConn{
		appID:      testAppID,
		responseCh: responseCh,
	}

	listener.connsLock.Lock()
	listener.conns[*testAppID] = mockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	// Create the EncryptRead request
	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("query-encrypt-rd"))

	request := &Request{
		AppID: testAppID,
		EncryptRead: &thin.EncryptRead{
			QueryID:         queryID,
			ReadCap:         readCap,
			MessageBoxIndex: messageBoxIndex,
		},
	}

	// Call encryptRead
	d.encryptRead(request)

	// Check the response
	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.EncryptReadReply)
		require.Equal(t, thin.ThinClientSuccess, resp.EncryptReadReply.ErrorCode)
		require.Equal(t, queryID, resp.EncryptReadReply.QueryID)
		require.NotEmpty(t, resp.EncryptReadReply.MessageCiphertext)
		require.NotEmpty(t, resp.EncryptReadReply.NextMessageIndex)
		require.NotEmpty(t, resp.EncryptReadReply.EnvelopeDescriptor)
		require.NotNil(t, resp.EncryptReadReply.EnvelopeHash)
		require.NotZero(t, resp.EncryptReadReply.ReplicaEpoch)
	case <-time.After(time.Second):
		t.Fatal("Expected a response but got none within timeout")
	}
}

func TestDaemonEncryptRead_NilReadCap(t *testing.T) {
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
		client:                    client,
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
	}

	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("test-nil-readcap"))

	responseCh := make(chan *Response, 1)
	mockConn := &mockIncomingConn{
		appID:      testAppID,
		responseCh: responseCh,
	}

	listener.connsLock.Lock()
	listener.conns[*testAppID] = mockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("query-nil-readcp"))

	// Create request with nil ReadCap
	request := &Request{
		AppID: testAppID,
		EncryptRead: &thin.EncryptRead{
			QueryID:         queryID,
			ReadCap:         nil, // nil ReadCap should cause error
			MessageBoxIndex: nil,
		},
	}

	d.encryptRead(request)

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.EncryptReadReply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.EncryptReadReply.ErrorCode)
	case <-time.After(time.Second):
		t.Fatal("Expected a response but got none within timeout")
	}
}

func TestDaemonEncryptWrite_Success(t *testing.T) {
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	port, err := getFreePort()
	require.NoError(t, err)
	cfg.ListenAddress = fmt.Sprintf("127.0.0.1:%d", port)

	// Add PigeonholeGeometry for write operations
	cfg.PigeonholeGeometry = &pigeonholeGeo.Geometry{
		MaxPlaintextPayloadLength: 1000,
		NIKEName:                  replicaCommon.NikeScheme.Name(),
	}

	client := &Client{cfg: cfg}
	rates := &Rates{}
	egressCh := make(chan *Request, 10)

	listener, err := NewListener(client, rates, egressCh, logBackend, nil)
	require.NoError(t, err)
	defer listener.Shutdown()

	// Create a mock PKI document and store it in the client
	doc := createMockPKIDocument(t)
	currentEpoch, _, _ := epochtime.Now()
	client.pki = &pki{
		c:    client,
		docs: sync.Map{},
	}
	client.pki.docs.Store(currentEpoch, &CachedDoc{
		Doc:  doc,
		Blob: nil,
	})

	d := &Daemon{
		cfg:                       cfg,
		logbackend:                logBackend,
		log:                       logBackend.GetLogger("test"),
		listener:                  listener,
		client:                    client,
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
	}

	// Create a WriteCap for testing
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)

	// Create a StatefulWriter to get a valid MessageBoxIndex
	statefulWriter, err := bacap.NewStatefulWriter(writeCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	messageBoxIndex := statefulWriter.GetCurrentMessageIndex()

	// Set up mock connection
	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("test-encryptwrite"))

	responseCh := make(chan *Response, 1)
	mockConn := &mockIncomingConn{
		appID:      testAppID,
		responseCh: responseCh,
	}

	listener.connsLock.Lock()
	listener.conns[*testAppID] = mockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	// Create the EncryptWrite request
	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("query-encrypt-wr"))

	plaintext := []byte("Hello, this is a test message for encryption!")

	request := &Request{
		AppID: testAppID,
		EncryptWrite: &thin.EncryptWrite{
			QueryID:         queryID,
			Plaintext:       plaintext,
			WriteCap:        writeCap,
			MessageBoxIndex: messageBoxIndex,
		},
	}

	// Call encryptWrite
	d.encryptWrite(request)

	// Check the response
	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.EncryptWriteReply)
		require.Equal(t, thin.ThinClientSuccess, resp.EncryptWriteReply.ErrorCode)
		require.Equal(t, queryID, resp.EncryptWriteReply.QueryID)
		require.NotEmpty(t, resp.EncryptWriteReply.MessageCiphertext)
		require.NotEmpty(t, resp.EncryptWriteReply.EnvelopeDescriptor)
		require.NotNil(t, resp.EncryptWriteReply.EnvelopeHash)
		require.NotZero(t, resp.EncryptWriteReply.ReplicaEpoch)
	case <-time.After(time.Second):
		t.Fatal("Expected a response but got none within timeout")
	}
}

func TestDaemonEncryptWrite_NilWriteCap(t *testing.T) {
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
		cfg:                       cfg,
		logbackend:                logBackend,
		log:                       logBackend.GetLogger("test"),
		listener:                  listener,
		client:                    client,
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
	}

	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("test-nil-writcap"))

	responseCh := make(chan *Response, 1)
	mockConn := &mockIncomingConn{
		appID:      testAppID,
		responseCh: responseCh,
	}

	listener.connsLock.Lock()
	listener.conns[*testAppID] = mockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("query-nil-wrtcap"))

	// Create request with nil WriteCap
	request := &Request{
		AppID: testAppID,
		EncryptWrite: &thin.EncryptWrite{
			QueryID:         queryID,
			Plaintext:       []byte("test"),
			WriteCap:        nil, // nil WriteCap should cause error
			MessageBoxIndex: nil,
		},
	}

	d.encryptWrite(request)

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.EncryptWriteReply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.EncryptWriteReply.ErrorCode)
	case <-time.After(time.Second):
		t.Fatal("Expected a response but got none within timeout")
	}
}
