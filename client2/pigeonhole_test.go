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

func TestARQCleanupOnAppDisconnect(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replies:                   make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:                    make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:                 new(sync.Mutex),
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newChannelMapXXX:          make(map[uint16]bool),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
	}

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d.logbackend = logBackend
	d.log = logBackend.GetLogger("test")

	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("test-app-id-1234"))

	otherAppID := &[AppIDLength]byte{}
	copy(otherAppID[:], []byte("other-app-id-567"))

	testSURBID1 := [sphinxConstants.SURBIDLength]byte{}
	testSURBID2 := [sphinxConstants.SURBIDLength]byte{}
	otherSURBID := [sphinxConstants.SURBIDLength]byte{}
	copy(testSURBID1[:], []byte("test-surb-id-001"))
	copy(testSURBID2[:], []byte("test-surb-id-002"))
	copy(otherSURBID[:], []byte("other-surb-id-01"))

	testQueryID := &[thin.QueryIDLength]byte{}
	copy(testQueryID[:], []byte("test-query-id1--"))

	d.replyLock.Lock()
	d.arqSurbIDMap[testSURBID1] = &ARQMessage{
		AppID:   testAppID,
		QueryID: testQueryID,
		SURBID:  &testSURBID1,
	}
	d.arqSurbIDMap[testSURBID2] = &ARQMessage{
		AppID:   testAppID,
		QueryID: testQueryID,
		SURBID:  &testSURBID2,
	}
	d.arqSurbIDMap[otherSURBID] = &ARQMessage{
		AppID:   otherAppID,
		QueryID: testQueryID,
		SURBID:  &otherSURBID,
	}
	d.replyLock.Unlock()

	d.replyLock.Lock()
	require.Len(t, d.arqSurbIDMap, 3)
	d.replyLock.Unlock()

	d.cleanupChannelsForAppID(testAppID)

	d.replyLock.Lock()
	require.NotContains(t, d.arqSurbIDMap, testSURBID1)
	require.NotContains(t, d.arqSurbIDMap, testSURBID2)
	require.Contains(t, d.arqSurbIDMap, otherSURBID)
	require.Len(t, d.arqSurbIDMap, 1)
	d.replyLock.Unlock()

	t.Log("ARQ cleanup test completed successfully")
}

func TestArqDoResendWithNilConnection(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replies:                   make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:                    make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:                 new(sync.Mutex),
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newChannelMapXXX:          make(map[uint16]bool),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
	}

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d.logbackend = logBackend
	d.log = logBackend.GetLogger("test")

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	port, err := getFreePort()
	require.NoError(t, err)
	cfg.ListenAddress = fmt.Sprintf("127.0.0.1:%d", port)

	client := &Client{
		cfg: cfg,
		pki: nil,
	}

	rates := &Rates{}
	egressCh := make(chan *Request, 10)

	d.listener, err = NewListener(client, rates, egressCh, logBackend, nil)
	require.NoError(t, err)

	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("disconnected-app"))

	testSURBID := [sphinxConstants.SURBIDLength]byte{}
	copy(testSURBID[:], []byte("test-surb-resend"))

	testQueryID := &[thin.QueryIDLength]byte{}
	copy(testQueryID[:], []byte("test-query-id1--"))

	d.replyLock.Lock()
	d.arqSurbIDMap[testSURBID] = &ARQMessage{
		AppID:           testAppID,
		QueryID:         testQueryID,
		SURBID:          &testSURBID,
		Retransmissions: 0,
	}
	d.replyLock.Unlock()

	require.NotPanics(t, func() {
		d.arqDoResend(&testSURBID)
	}, "arqDoResend should not panic when connection is nil")

	d.replyLock.Lock()
	_, exists := d.arqSurbIDMap[testSURBID]
	d.replyLock.Unlock()
	// Note: with the new ARQ, entries may not be cleaned up on first resend failure
	// since we retry forever. This test just verifies no panic occurs.
	_ = exists

	d.listener.Shutdown()
	t.Log("arqDoResend nil connection test completed successfully - no panic occurred")
}

func TestArqDoResendWithHighRetryCountAndNilConnection(t *testing.T) {
	// This test verifies that the ARQ continues to work even after many retries
	// since the new Pigeonhole ARQ retries forever until cancelled.
	d := &Daemon{
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replies:                   make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:                    make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:                 new(sync.Mutex),
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newChannelMapXXX:          make(map[uint16]bool),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
	}

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d.logbackend = logBackend
	d.log = logBackend.GetLogger("test")

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	port, err := getFreePort()
	require.NoError(t, err)
	cfg.ListenAddress = fmt.Sprintf("127.0.0.1:%d", port)

	client := &Client{
		cfg: cfg,
		pki: nil,
	}

	rates := &Rates{}
	egressCh := make(chan *Request, 10)

	d.listener, err = NewListener(client, rates, egressCh, logBackend, nil)
	require.NoError(t, err)

	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("disconnected-app"))

	testSURBID := [sphinxConstants.SURBIDLength]byte{}
	copy(testSURBID[:], []byte("test-surb-maxret"))

	testQueryID := &[thin.QueryIDLength]byte{}
	copy(testQueryID[:], []byte("test-query-id1--"))

	d.replyLock.Lock()
	d.arqSurbIDMap[testSURBID] = &ARQMessage{
		AppID:           testAppID,
		QueryID:         testQueryID,
		SURBID:          &testSURBID,
		Retransmissions: 100, // High retry count - ARQ still works
	}
	d.replyLock.Unlock()

	require.NotPanics(t, func() {
		d.arqDoResend(&testSURBID)
	}, "arqDoResend should not panic at high retry count when connection is nil")

	d.listener.Shutdown()
	t.Log("arqDoResend high retry count with nil connection test completed successfully")
}

func TestRaceConditionARQResendAfterDisconnect(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replies:                   make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:                    make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:                 new(sync.Mutex),
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newChannelMapXXX:          make(map[uint16]bool),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
	}

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d.logbackend = logBackend
	d.log = logBackend.GetLogger("test")

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	port, err := getFreePort()
	require.NoError(t, err)
	cfg.ListenAddress = fmt.Sprintf("127.0.0.1:%d", port)

	client := &Client{
		cfg: cfg,
		pki: nil,
	}

	rates := &Rates{}
	egressCh := make(chan *Request, 10)

	d.listener, err = NewListener(client, rates, egressCh, logBackend, nil)
	require.NoError(t, err)

	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("race-test-app-id"))

	var surbIDs [][sphinxConstants.SURBIDLength]byte
	for i := 0; i < 10; i++ {
		surbID := [sphinxConstants.SURBIDLength]byte{}
		copy(surbID[:], []byte(fmt.Sprintf("race-surb-id-%03d", i)))
		surbIDs = append(surbIDs, surbID)

		queryID := &[thin.QueryIDLength]byte{}
		copy(queryID[:], []byte(fmt.Sprintf("race-qid-%06d", i)))

		d.replyLock.Lock()
		d.arqSurbIDMap[surbID] = &ARQMessage{
			AppID:           testAppID,
			QueryID:         queryID,
			SURBID:          &surbID,
			Retransmissions: uint32(i % 10),
		}
		d.replyLock.Unlock()
	}

	var wg sync.WaitGroup
	panicChan := make(chan interface{}, 20)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				panicChan <- r
			}
		}()
		time.Sleep(5 * time.Millisecond)
		d.cleanupChannelsForAppID(testAppID)
	}()

	for _, surbID := range surbIDs {
		surbIDCopy := surbID
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicChan <- r
				}
			}()
			time.Sleep(time.Duration(1+testAppID[0]%10) * time.Millisecond)
			d.arqDoResend(&surbIDCopy)
		}()
	}

	wg.Wait()
	close(panicChan)

	var panics []interface{}
	for p := range panicChan {
		panics = append(panics, p)
	}
	require.Empty(t, panics, "No panics should occur during concurrent cleanup and resend operations")

	d.replyLock.Lock()
	arqCount := len(d.arqSurbIDMap)
	d.replyLock.Unlock()
	require.Equal(t, 0, arqCount, "All ARQ entries for the disconnected client should be cleaned up")

	d.listener.Shutdown()
	t.Log("Race condition test completed successfully - no panics during concurrent operations")
}

func TestArqDoResendWithNilListener(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replies:                   make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:                    make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:                 new(sync.Mutex),
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newChannelMapXXX:          make(map[uint16]bool),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
		listener:                  nil,
	}

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d.logbackend = logBackend
	d.log = logBackend.GetLogger("test")

	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("nil-listener-app"))

	testSURBID := [sphinxConstants.SURBIDLength]byte{}
	copy(testSURBID[:], []byte("nil-listener-sur"))

	testQueryID := &[thin.QueryIDLength]byte{}
	copy(testQueryID[:], []byte("nil-list-qid1---"))

	d.replyLock.Lock()
	d.arqSurbIDMap[testSURBID] = &ARQMessage{
		AppID:           testAppID,
		QueryID:         testQueryID,
		SURBID:          &testSURBID,
		Retransmissions: 0,
	}
	d.replyLock.Unlock()

	require.NotPanics(t, func() {
		d.arqDoResend(&testSURBID)
	}, "arqDoResend should not panic when listener is nil")

	// Note: with the new ARQ, entries may not be cleaned up on first resend failure
	// since we retry forever. This test just verifies no panic occurs.

	t.Log("arqDoResend nil listener test completed successfully")
}
