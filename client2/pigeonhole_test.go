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
	"github.com/katzenpost/hpqc/nike"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	sphinxCommands "github.com/katzenpost/katzenpost/core/sphinx/commands"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/pigeonhole"
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
				AppID:                                m.appID,
				NewKeypairReply:                      thinResp.NewKeypairReply,
				EncryptReadReply:                     thinResp.EncryptReadReply,
				EncryptWriteReply:                    thinResp.EncryptWriteReply,
				StartResendingEncryptedMessageReply:  thinResp.StartResendingEncryptedMessageReply,
				CancelResendingEncryptedMessageReply: thinResp.CancelResendingEncryptedMessageReply,
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
	configuredReplicaKeys := make([][]byte, 2)

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

		// Store identity key for ConfiguredReplicaIdentityKeys
		configuredReplicaKeys[i] = make([]byte, len(identityKey))
		copy(configuredReplicaKeys[i], identityKey)
	}

	return &cpki.Document{
		Epoch:                         currentEpoch,
		StorageReplicas:               replicaDescriptors,
		ConfiguredReplicaIdentityKeys: configuredReplicaKeys,
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
		log:  logBackend.GetLogger("pki"),
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
		log:  logBackend.GetLogger("pki"),
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

// TestAliceSendsBobMessage tests the complete end-to-end flow of Alice sending Bob a message
// using the new Pigeonhole API. This test simulates:
// 1. Alice creates a WriteCap and gives Bob the ReadCap
// 2. Alice encrypts a message using encryptWrite
// 3. Bob encrypts a read request using encryptRead
// 4. Bob decrypts Alice's message
func TestAliceSendsBobMessage(t *testing.T) {
	require := require.New(t)

	logBackend, err := log.New("", "debug", false)
	require.NoError(err)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	port, err := getFreePort()
	require.NoError(err)
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
	require.NoError(err)
	defer listener.Shutdown()

	// Create a mock PKI document
	doc := createMockPKIDocument(t)
	currentEpoch, _, _ := epochtime.Now()
	client.pki = &pki{
		c:               client,
		log:             logBackend.GetLogger("pki"),
		docs:            sync.Map{},
		consensusGetter: &mockConsensusGetter{},
	}
	client.pki.docs.Store(currentEpoch, &CachedDoc{
		Doc:  doc,
		Blob: nil,
	})

	d := &Daemon{
		logbackend:                logBackend,
		log:                       logBackend.GetLogger("test-alice-bob"),
		listener:                  listener,
		client:                    client,
		cfg:                       cfg,
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
	}

	t.Log("=== Step 1: Alice creates WriteCap and derives ReadCap for Bob ===")

	// Alice creates a new keypair
	aliceSeed := make([]byte, 32)
	_, err = rand.Reader.Read(aliceSeed)
	require.NoError(err)

	aliceRng, err := rand.NewDeterministicRandReader(aliceSeed)
	require.NoError(err)

	aliceWriteCap, err := bacap.NewWriteCap(aliceRng)
	require.NoError(err)
	require.NotNil(aliceWriteCap)

	// Alice derives ReadCap for Bob
	bobReadCap := aliceWriteCap.ReadCap()
	require.NotNil(bobReadCap)
	t.Logf("   ✓ Alice created WriteCap and derived ReadCap for Bob")

	t.Log("=== Step 2: Alice encrypts a message for Bob ===")

	// Alice's message to Bob
	aliceMessage := []byte("Bob, Beware they are jamming GPS.")

	// Set up Alice's mock connection
	aliceAppID := &[AppIDLength]byte{}
	copy(aliceAppID[:], []byte("alice-app-id----"))

	aliceResponseCh := make(chan *Response, 1)
	aliceMockConn := &mockIncomingConn{
		appID:      aliceAppID,
		responseCh: aliceResponseCh,
	}

	listener.connsLock.Lock()
	listener.conns[*aliceAppID] = aliceMockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	// Alice gets the current MessageBoxIndex from her WriteCap
	aliceStatefulWriter, err := bacap.NewStatefulWriter(aliceWriteCap, constants.PIGEONHOLE_CTX)
	require.NoError(err)
	aliceMessageBoxIndex := aliceStatefulWriter.GetCurrentMessageIndex()

	// Alice creates an EncryptWrite request
	aliceQueryID := &[thin.QueryIDLength]byte{}
	copy(aliceQueryID[:], []byte("alice-write-qry-"))

	aliceWriteRequest := &Request{
		AppID: aliceAppID,
		EncryptWrite: &thin.EncryptWrite{
			QueryID:         aliceQueryID,
			Plaintext:       aliceMessage,
			WriteCap:        aliceWriteCap,
			MessageBoxIndex: aliceMessageBoxIndex,
		},
	}

	// Alice calls encryptWrite
	d.encryptWrite(aliceWriteRequest)

	// Get Alice's encrypted write response
	select {
	case resp := <-aliceResponseCh:
		require.NotNil(resp.EncryptWriteReply)
		require.Equal(thin.ThinClientSuccess, resp.EncryptWriteReply.ErrorCode)
		t.Logf("   ✓ Alice encrypted message: %d bytes plaintext -> %d bytes ciphertext",
			len(aliceMessage), len(resp.EncryptWriteReply.MessageCiphertext))
	case <-time.After(time.Second):
		t.Fatal("Expected Alice's write response but got none within timeout")
	}

	t.Log("=== Step 3: Bob encrypts a read request ===")

	// Set up Bob's mock connection
	bobAppID := &[AppIDLength]byte{}
	copy(bobAppID[:], []byte("bob-app-id------"))

	bobResponseCh := make(chan *Response, 1)
	bobMockConn := &mockIncomingConn{
		appID:      bobAppID,
		responseCh: bobResponseCh,
	}

	listener.connsLock.Lock()
	listener.conns[*bobAppID] = bobMockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	// Bob creates a StatefulReader from the ReadCap Alice gave him
	// Bob starts reading from the same MessageBoxIndex that Alice wrote to
	bobStatefulReader, err := bacap.NewStatefulReaderWithIndex(bobReadCap, constants.PIGEONHOLE_CTX, aliceMessageBoxIndex)
	require.NoError(err)

	// Bob creates an EncryptRead request
	bobQueryID := &[thin.QueryIDLength]byte{}
	copy(bobQueryID[:], []byte("bob-read-query--"))

	bobReadRequest := &Request{
		AppID: bobAppID,
		EncryptRead: &thin.EncryptRead{
			QueryID:         bobQueryID,
			ReadCap:         bobReadCap,
			MessageBoxIndex: aliceMessageBoxIndex,
		},
	}

	// Bob calls encryptRead
	d.encryptRead(bobReadRequest)

	// Get Bob's encrypted read response
	select {
	case resp := <-bobResponseCh:
		require.NotNil(resp.EncryptReadReply)
		require.Equal(thin.ThinClientSuccess, resp.EncryptReadReply.ErrorCode)
		t.Logf("   ✓ Bob created read request: %d bytes", len(resp.EncryptReadReply.MessageCiphertext))
	case <-time.After(time.Second):
		t.Fatal("Expected Bob's read response but got none within timeout")
	}

	t.Log("=== Step 4: Verify BoxIDs match (Alice's write and Bob's read target the same box) ===")

	// Verify that both Alice and Bob are targeting the same BoxID
	// by using the BACAP API directly
	aliceBoxID, err := aliceStatefulWriter.NextBoxID()
	require.NoError(err)

	bobBoxID, err := bobStatefulReader.NextBoxID()
	require.NoError(err)

	require.Equal(aliceBoxID.Bytes(), bobBoxID[:], "Alice's write BoxID should match Bob's read BoxID")
	t.Logf("   ✓ BoxIDs match: %x...", aliceBoxID.Bytes()[:8])

	t.Log("=== Step 5: Simulate Bob decrypting Alice's message ===")

	// In a real scenario, the courier would forward Alice's write to the replicas,
	// and Bob's read would retrieve it. Here we simulate Bob decrypting directly
	// using the BACAP primitives.

	// Get the BoxID, ciphertext, and signature that Alice created
	aliceBoxIDFromWriter, aliceCiphertext, aliceSigRaw, err := aliceStatefulWriter.PrepareNext(aliceMessage)
	require.NoError(err)

	aliceSig := [bacap.SignatureSize]byte{}
	copy(aliceSig[:], aliceSigRaw)

	// Bob decrypts using his StatefulReader
	bobDecrypted, err := bobStatefulReader.DecryptNext(constants.PIGEONHOLE_CTX, aliceBoxIDFromWriter, aliceCiphertext, aliceSig)
	require.NoError(err)

	require.Equal(aliceMessage, bobDecrypted, "Bob should decrypt Alice's original message")
	t.Logf("   ✓ Bob successfully decrypted Alice's message: %q", string(bobDecrypted))

	t.Log("=== ✓ End-to-end test complete: Alice successfully sent Bob a message! ===")
}

// TestAliceSendsMultipleMessagesToBob tests Alice sending multiple sequential messages to Bob
// using the new Pigeonhole API with proper state advancement.
func TestAliceSendsMultipleMessagesToBob(t *testing.T) {
	require := require.New(t)

	logBackend, err := log.New("", "debug", false)
	require.NoError(err)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	port, err := getFreePort()
	require.NoError(err)
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
	require.NoError(err)
	defer listener.Shutdown()

	// Create a mock PKI document
	doc := createMockPKIDocument(t)
	currentEpoch, _, _ := epochtime.Now()
	client.pki = &pki{
		c:    client,
		log:  logBackend.GetLogger("pki"),
		docs: sync.Map{},
	}
	client.pki.docs.Store(currentEpoch, &CachedDoc{
		Doc:  doc,
		Blob: nil,
	})

	d := &Daemon{
		logbackend:                logBackend,
		log:                       logBackend.GetLogger("test-multi-msg"),
		listener:                  listener,
		client:                    client,
		cfg:                       cfg,
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap:        make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		replyLock:                 new(sync.Mutex),
	}

	t.Log("=== Setup: Alice creates WriteCap and gives Bob the ReadCap ===")

	// Alice creates a new keypair
	aliceSeed := make([]byte, 32)
	_, err = rand.Reader.Read(aliceSeed)
	require.NoError(err)

	aliceRng, err := rand.NewDeterministicRandReader(aliceSeed)
	require.NoError(err)

	aliceWriteCap, err := bacap.NewWriteCap(aliceRng)
	require.NoError(err)

	bobReadCap := aliceWriteCap.ReadCap()
	require.NotNil(bobReadCap)

	// Create stateful writer and reader
	aliceStatefulWriter, err := bacap.NewStatefulWriter(aliceWriteCap, constants.PIGEONHOLE_CTX)
	require.NoError(err)

	bobStatefulReader, err := bacap.NewStatefulReader(bobReadCap, constants.PIGEONHOLE_CTX)
	require.NoError(err)

	// Set up Alice's mock connection
	aliceAppID := &[AppIDLength]byte{}
	copy(aliceAppID[:], []byte("alice-multi-msg-"))

	aliceResponseCh := make(chan *Response, 10)
	aliceMockConn := &mockIncomingConn{
		appID:      aliceAppID,
		responseCh: aliceResponseCh,
	}

	listener.connsLock.Lock()
	listener.conns[*aliceAppID] = aliceMockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	// Set up Bob's mock connection
	bobAppID := &[AppIDLength]byte{}
	copy(bobAppID[:], []byte("bob-multi-msg---"))

	bobResponseCh := make(chan *Response, 10)
	bobMockConn := &mockIncomingConn{
		appID:      bobAppID,
		responseCh: bobResponseCh,
	}

	listener.connsLock.Lock()
	listener.conns[*bobAppID] = bobMockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	t.Log("=== Testing: Alice sends 5 sequential messages to Bob ===")

	numMessages := 5
	for i := 0; i < numMessages; i++ {
		message := []byte(fmt.Sprintf("Message %d from Alice to Bob", i))
		t.Logf("\n--- Message %d ---", i)

		// Alice gets current MessageBoxIndex
		aliceMessageBoxIndex := aliceStatefulWriter.GetCurrentMessageIndex()

		// Alice encrypts the message
		aliceQueryID := &[thin.QueryIDLength]byte{}
		copy(aliceQueryID[:], []byte(fmt.Sprintf("alice-msg-%d-----", i)))

		aliceWriteRequest := &Request{
			AppID: aliceAppID,
			EncryptWrite: &thin.EncryptWrite{
				QueryID:         aliceQueryID,
				Plaintext:       message,
				WriteCap:        aliceWriteCap,
				MessageBoxIndex: aliceMessageBoxIndex,
			},
		}

		d.encryptWrite(aliceWriteRequest)

		// Get Alice's response
		select {
		case resp := <-aliceResponseCh:
			require.NotNil(resp.EncryptWriteReply)
			require.Equal(thin.ThinClientSuccess, resp.EncryptWriteReply.ErrorCode)
			t.Logf("   ✓ Alice encrypted message %d", i)
		case <-time.After(time.Second):
			t.Fatalf("Expected Alice's write response for message %d but got none", i)
		}

		// Get the encrypted data using PrepareNext (doesn't advance state)
		aliceBoxID, aliceCiphertext, aliceSigRaw, err := aliceStatefulWriter.PrepareNext(message)
		require.NoError(err)

		aliceSig := [bacap.SignatureSize]byte{}
		copy(aliceSig[:], aliceSigRaw)

		// Bob decrypts the message
		bobDecrypted, err := bobStatefulReader.DecryptNext(constants.PIGEONHOLE_CTX, aliceBoxID, aliceCiphertext, aliceSig)
		require.NoError(err)
		require.Equal(message, bobDecrypted)
		t.Logf("   ✓ Bob decrypted message %d: %q", i, string(bobDecrypted))

		// Simulate ACK: Alice advances her state after successful write
		err = aliceStatefulWriter.AdvanceState()
		require.NoError(err)
		t.Logf("   ✓ Alice advanced state after ACK for message %d", i)

		// Verify that Alice and Bob's indices are in sync
		aliceNextIdx := aliceStatefulWriter.GetCurrentMessageIndex().Idx64
		bobNextIdx := bobStatefulReader.GetCurrentMessageIndex().Idx64
		require.Equal(aliceNextIdx, bobNextIdx, "Alice and Bob should be at the same index")
		t.Logf("   ✓ Alice and Bob indices in sync: %d", aliceNextIdx)
	}

	t.Log("=== ✓ Multi-message test complete: Alice sent 5 messages to Bob successfully! ===")
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

// TestARQSuccessWriteACK tests the ARQ success code path for write operations (ACK).
// This tests the full path: SURB reply arrives -> handlePigeonholeARQReply -> success response sent.
func TestARQSuccessWriteACK(t *testing.T) {
	require := require.New(t)

	// Create a minimal daemon with required fields
	logBackend, err := log.New("", "debug", false)
	require.NoError(err)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	port, err := getFreePort()
	require.NoError(err)
	cfg.ListenAddress = fmt.Sprintf("127.0.0.1:%d", port)

	// Create the Sphinx instance for SURB operations
	sphinxInstance, err := sphinx.FromGeometry(cfg.SphinxGeometry)
	require.NoError(err)

	// Create a Client with the sphinx instance
	client := &Client{
		cfg:    cfg,
		sphinx: sphinxInstance,
		geo:    cfg.SphinxGeometry,
	}

	rates := &Rates{}
	egressCh := make(chan *Request, 10)

	listener, err := NewListener(client, rates, egressCh, logBackend, nil)
	require.NoError(err)
	defer listener.Shutdown()

	d := &Daemon{
		logbackend:                logBackend,
		log:                       logBackend.GetLogger("test"),
		client:                    client,
		listener:                  listener,
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap:        make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		replies:                   make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:                    make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:                 new(sync.Mutex),
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
	}

	// Generate test identifiers
	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("arq-success-appid"))

	testQueryID := &[thin.QueryIDLength]byte{}
	copy(testQueryID[:], []byte("arq-success-qryid"))

	testEnvelopeHash := &[32]byte{}
	copy(testEnvelopeHash[:], []byte("arq-success-envelope-hash123"))

	// Create a SURB path for testing
	nrHops := 5
	nodes, path := createNikePathVector(require, cfg.SphinxGeometry.NIKEName, nrHops)

	// Create the SURB
	surb, surbKeys, err := sphinxInstance.NewSURB(rand.Reader, path)
	require.NoError(err)

	// Extract the SURB ID from the SURB (first 16 bytes after parsing)
	testSURBID := &[sphinxConstants.SURBIDLength]byte{}
	copy(testSURBID[:], surb[:sphinxConstants.SURBIDLength])

	// Create a CourierQueryReply with ReplyType=0 (envelope reply) and
	// CourierEnvelopeReply with ReplyType=0 (ACK) and ErrorCode=0 (success)
	courierEnvelopeReply := &pigeonhole.CourierEnvelopeReply{
		EnvelopeHash: *testEnvelopeHash,
		ReplyIndex:   0,
		ReplyType:    pigeonhole.ReplyTypeACK, // ACK for write success
		PayloadLen:   0,
		Payload:      []byte{},
		ErrorCode:    0, // Success
	}

	courierQueryReply := &pigeonhole.CourierQueryReply{
		ReplyType:     0, // envelope reply
		EnvelopeReply: courierEnvelopeReply,
	}

	// Serialize the CourierQueryReply
	replyPayload, err := courierQueryReply.MarshalBinary()
	require.NoError(err)

	// Pad the payload to the expected forward payload length
	paddedPayload := make([]byte, cfg.SphinxGeometry.ForwardPayloadLength)
	copy(paddedPayload, replyPayload)

	// Create a reply packet using the SURB
	pkt, _, err := sphinxInstance.NewPacketFromSURB(surb, paddedPayload)
	require.NoError(err)

	// Unwrap the packet through all hops to get the final ciphertext
	var finalCiphertext []byte
	for i := range nodes {
		b, _, _, err := sphinxInstance.Unwrap(nodes[i].privateKey, pkt)
		require.NoErrorf(err, "Hop %d: Unwrap failed", i)
		if i == len(path)-1 {
			// At the final hop, b contains the encrypted payload
			finalCiphertext = b
		}
	}
	require.NotNil(finalCiphertext)

	// Set up the mock connection to receive responses
	responseCh := make(chan *Response, 1)
	mockConn := &mockIncomingConn{
		appID:      testAppID,
		responseCh: responseCh,
	}

	// Register the mock connection
	listener.connsLock.Lock()
	listener.conns[*testAppID] = mockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	// Register the ARQ message in the daemon's maps
	arqMessage := &ARQMessage{
		AppID:              testAppID,
		QueryID:            testQueryID,
		EnvelopeHash:       testEnvelopeHash,
		SURBID:             testSURBID,
		SURBDecryptionKeys: surbKeys,
		IsRead:             false, // Write operation
	}

	d.replyLock.Lock()
	d.arqSurbIDMap[*testSURBID] = arqMessage
	d.arqEnvelopeHashMap[*testEnvelopeHash] = testSURBID
	d.replyLock.Unlock()

	// Create the sphinxReply that would come from the mixnet
	reply := &sphinxReply{
		surbID:     testSURBID,
		ciphertext: finalCiphertext,
	}

	// Call handlePigeonholeARQReply directly
	d.handlePigeonholeARQReply(arqMessage, reply)

	// Verify the response
	select {
	case resp := <-responseCh:
		require.NotNil(resp.StartResendingEncryptedMessageReply)
		require.Equal(thin.ThinClientSuccess, resp.StartResendingEncryptedMessageReply.ErrorCode)
		require.Equal(testQueryID, resp.StartResendingEncryptedMessageReply.QueryID)
		require.Empty(resp.StartResendingEncryptedMessageReply.Plaintext) // ACK has no plaintext
		t.Logf("ARQ success write ACK test passed - received success response with ErrorCode=%d",
			resp.StartResendingEncryptedMessageReply.ErrorCode)
	case <-time.After(2 * time.Second):
		t.Fatal("Expected a response but got none within timeout")
	}
}

// createNikePathVector creates a path of nodes for SURB testing
func createNikePathVector(require *require.Assertions, nikeName string, nrHops int) ([]*nikeNodeParams, []*sphinx.PathHop) {
	nikeScheme := nikeSchemes.ByName(nikeName)
	require.NotNil(nikeScheme, "failed to find NIKE scheme: %s", nikeName)

	const delayBase = 0xdeadbabe

	// Generate the keypairs and node identifiers for the "nodes"
	nodes := make([]*nikeNodeParams, nrHops)
	for i := range nodes {
		nodes[i] = &nikeNodeParams{}
		_, err := rand.Reader.Read(nodes[i].id[:])
		require.NoError(err, "failed to generate ID")
		nodes[i].publicKey, nodes[i].privateKey, err = nikeScheme.GenerateKeyPair()
		require.NoError(err, "GenerateKeyPair failed")
	}

	// Assemble the path vector
	path := make([]*sphinx.PathHop, nrHops)
	for i := range path {
		path[i] = new(sphinx.PathHop)
		copy(path[i].ID[:], nodes[i].id[:])
		path[i].NIKEPublicKey = nodes[i].publicKey
		if i < nrHops-1 {
			// Non-terminal hop, add the delay
			delay := new(sphinxCommands.NodeDelay)
			delay.Delay = delayBase * uint32(i+1)
			path[i].Commands = append(path[i].Commands, delay)
		} else {
			// Terminal hop, add the recipient
			recipient := new(sphinxCommands.Recipient)
			_, err := rand.Reader.Read(recipient.ID[:])
			require.NoError(err, "failed to generate recipient")
			path[i].Commands = append(path[i].Commands, recipient)

			// This is a SURB, add a surb_reply
			surbReply := new(sphinxCommands.SURBReply)
			_, err = rand.Reader.Read(surbReply.ID[:])
			require.NoError(err, "failed to generate surb_reply")
			path[i].Commands = append(path[i].Commands, surbReply)
		}
	}

	return nodes, path
}

// nikeNodeParams holds node parameters for SURB path testing
type nikeNodeParams struct {
	id         [sphinxConstants.NodeIDLength]byte
	privateKey nike.PrivateKey
	publicKey  nike.PublicKey
}

// TestStartResendingEncryptedMessage_ValidationErrors tests the validation logic
// in startResendingEncryptedMessage without needing a full mixnet.
func TestStartResendingEncryptedMessage_ValidationErrors(t *testing.T) {
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
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap:        make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		replyLock:                 new(sync.Mutex),
	}

	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("test-start-resnd"))

	responseCh := make(chan *Response, 10)
	mockConn := &mockIncomingConn{
		appID:      testAppID,
		responseCh: responseCh,
	}

	listener.connsLock.Lock()
	listener.conns[*testAppID] = mockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("test-query-id---"))

	envelopeHash := &[32]byte{}
	copy(envelopeHash[:], []byte("test-envelope-hash----------"))

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)

	// Test 1: nil QueryID
	t.Run("nil QueryID", func(t *testing.T) {
		request := &Request{
			AppID: testAppID,
			StartResendingEncryptedMessage: &thin.StartResendingEncryptedMessage{
				QueryID:            nil,
				EnvelopeHash:       envelopeHash,
				MessageCiphertext:  []byte("test"),
				EnvelopeDescriptor: []byte("desc"),
				WriteCap:           writeCap,
			},
		}
		d.startResendingEncryptedMessage(request)

		select {
		case resp := <-responseCh:
			require.NotNil(t, resp.StartResendingEncryptedMessageReply)
			require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.StartResendingEncryptedMessageReply.ErrorCode)
		case <-time.After(time.Second):
			t.Fatal("Expected error response")
		}
	})

	// Test 2: nil EnvelopeHash
	t.Run("nil EnvelopeHash", func(t *testing.T) {
		request := &Request{
			AppID: testAppID,
			StartResendingEncryptedMessage: &thin.StartResendingEncryptedMessage{
				QueryID:            queryID,
				EnvelopeHash:       nil,
				MessageCiphertext:  []byte("test"),
				EnvelopeDescriptor: []byte("desc"),
				WriteCap:           writeCap,
			},
		}
		d.startResendingEncryptedMessage(request)

		select {
		case resp := <-responseCh:
			require.NotNil(t, resp.StartResendingEncryptedMessageReply)
			require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.StartResendingEncryptedMessageReply.ErrorCode)
		case <-time.After(time.Second):
			t.Fatal("Expected error response")
		}
	})

	// Test 3: empty MessageCiphertext
	t.Run("empty MessageCiphertext", func(t *testing.T) {
		request := &Request{
			AppID: testAppID,
			StartResendingEncryptedMessage: &thin.StartResendingEncryptedMessage{
				QueryID:            queryID,
				EnvelopeHash:       envelopeHash,
				MessageCiphertext:  []byte{},
				EnvelopeDescriptor: []byte("desc"),
				WriteCap:           writeCap,
			},
		}
		d.startResendingEncryptedMessage(request)

		select {
		case resp := <-responseCh:
			require.NotNil(t, resp.StartResendingEncryptedMessageReply)
			require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.StartResendingEncryptedMessageReply.ErrorCode)
		case <-time.After(time.Second):
			t.Fatal("Expected error response")
		}
	})

	// Test 4: empty EnvelopeDescriptor
	t.Run("empty EnvelopeDescriptor", func(t *testing.T) {
		request := &Request{
			AppID: testAppID,
			StartResendingEncryptedMessage: &thin.StartResendingEncryptedMessage{
				QueryID:            queryID,
				EnvelopeHash:       envelopeHash,
				MessageCiphertext:  []byte("test"),
				EnvelopeDescriptor: []byte{},
				WriteCap:           writeCap,
			},
		}
		d.startResendingEncryptedMessage(request)

		select {
		case resp := <-responseCh:
			require.NotNil(t, resp.StartResendingEncryptedMessageReply)
			require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.StartResendingEncryptedMessageReply.ErrorCode)
		case <-time.After(time.Second):
			t.Fatal("Expected error response")
		}
	})

	// Test 5: neither ReadCap nor WriteCap set
	t.Run("no capability set", func(t *testing.T) {
		request := &Request{
			AppID: testAppID,
			StartResendingEncryptedMessage: &thin.StartResendingEncryptedMessage{
				QueryID:            queryID,
				EnvelopeHash:       envelopeHash,
				MessageCiphertext:  []byte("test"),
				EnvelopeDescriptor: []byte("desc"),
				ReadCap:            nil,
				WriteCap:           nil,
			},
		}
		d.startResendingEncryptedMessage(request)

		select {
		case resp := <-responseCh:
			require.NotNil(t, resp.StartResendingEncryptedMessageReply)
			require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.StartResendingEncryptedMessageReply.ErrorCode)
		case <-time.After(time.Second):
			t.Fatal("Expected error response")
		}
	})

	// Test 6: both ReadCap and WriteCap set
	t.Run("both capabilities set", func(t *testing.T) {
		readCap := writeCap.ReadCap()
		request := &Request{
			AppID: testAppID,
			StartResendingEncryptedMessage: &thin.StartResendingEncryptedMessage{
				QueryID:            queryID,
				EnvelopeHash:       envelopeHash,
				MessageCiphertext:  []byte("test"),
				EnvelopeDescriptor: []byte("desc"),
				ReadCap:            readCap,
				WriteCap:           writeCap,
			},
		}
		d.startResendingEncryptedMessage(request)

		select {
		case resp := <-responseCh:
			require.NotNil(t, resp.StartResendingEncryptedMessageReply)
			require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.StartResendingEncryptedMessageReply.ErrorCode)
		case <-time.After(time.Second):
			t.Fatal("Expected error response")
		}
	})

	t.Log("All startResendingEncryptedMessage validation tests passed")
}

// TestCancelResendingEncryptedMessage tests the cancel functionality
func TestCancelResendingEncryptedMessage(t *testing.T) {
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
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap:        make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		replyLock:                 new(sync.Mutex),
	}

	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("test-cancel-rsnd"))

	responseCh := make(chan *Response, 10)
	mockConn := &mockIncomingConn{
		appID:      testAppID,
		responseCh: responseCh,
	}

	listener.connsLock.Lock()
	listener.conns[*testAppID] = mockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("cancel-query-id-"))

	envelopeHash := &[32]byte{}
	copy(envelopeHash[:], []byte("cancel-envelope-hash--------"))

	surbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(surbID[:], []byte("cancel-surb-id--"))

	// Pre-populate the ARQ maps to simulate an in-flight message
	d.replyLock.Lock()
	d.arqSurbIDMap[*surbID] = &ARQMessage{
		AppID:        testAppID,
		QueryID:      queryID,
		EnvelopeHash: envelopeHash,
		SURBID:       surbID,
	}
	d.arqEnvelopeHashMap[*envelopeHash] = surbID
	d.replyLock.Unlock()

	// Verify the maps are populated
	d.replyLock.Lock()
	require.Len(t, d.arqSurbIDMap, 1)
	require.Len(t, d.arqEnvelopeHashMap, 1)
	d.replyLock.Unlock()

	// Test 1: Cancel existing message
	t.Run("cancel existing message", func(t *testing.T) {
		// Use a different QueryID for the cancel request than the original StartResendingEncryptedMessage
		cancelQueryID := &[thin.QueryIDLength]byte{}
		copy(cancelQueryID[:], []byte("cancel-query-id2"))

		request := &Request{
			AppID: testAppID,
			CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
				QueryID:      cancelQueryID,
				EnvelopeHash: envelopeHash,
			},
		}
		d.cancelResendingEncryptedMessage(request)

		// We should receive TWO responses:
		// 1. StartResendingEncryptedMessageReply with cancellation error (to the original StartResendingEncryptedMessage)
		// 2. CancelResendingEncryptedMessageReply with success (to the CancelResendingEncryptedMessage call)

		receivedStartReply := false
		receivedCancelReply := false

		for i := 0; i < 2; i++ {
			select {
			case resp := <-responseCh:
				if resp.StartResendingEncryptedMessageReply != nil {
					// This should be the cancellation notification to the original StartResendingEncryptedMessage
					require.Equal(t, queryID, resp.StartResendingEncryptedMessageReply.QueryID,
						"StartResendingEncryptedMessageReply should have the original query ID")
					require.Equal(t, thin.ThinClientErrorStartResendingCancelled, resp.StartResendingEncryptedMessageReply.ErrorCode,
						"StartResendingEncryptedMessageReply should have cancellation error code")
					require.Nil(t, resp.StartResendingEncryptedMessageReply.Plaintext,
						"StartResendingEncryptedMessageReply should have nil plaintext on cancellation")
					receivedStartReply = true
				} else if resp.CancelResendingEncryptedMessageReply != nil {
					// This should be the success response to CancelResendingEncryptedMessage
					require.Equal(t, cancelQueryID, resp.CancelResendingEncryptedMessageReply.QueryID,
						"CancelResendingEncryptedMessageReply should have the cancel query ID")
					require.Equal(t, thin.ThinClientSuccess, resp.CancelResendingEncryptedMessageReply.ErrorCode,
						"CancelResendingEncryptedMessageReply should have success error code")
					receivedCancelReply = true
				} else {
					t.Fatal("Received unexpected response type")
				}
			case <-time.After(time.Second):
				t.Fatalf("Timeout waiting for response %d/2", i+1)
			}
		}

		require.True(t, receivedStartReply, "Should have received StartResendingEncryptedMessageReply")
		require.True(t, receivedCancelReply, "Should have received CancelResendingEncryptedMessageReply")

		// Verify the maps are now empty
		d.replyLock.Lock()
		require.Len(t, d.arqSurbIDMap, 0, "arqSurbIDMap should be empty after cancel")
		require.Len(t, d.arqEnvelopeHashMap, 0, "arqEnvelopeHashMap should be empty after cancel")
		d.replyLock.Unlock()
	})

	// Test 2: Cancel non-existent message (should still succeed)
	t.Run("cancel non-existent message", func(t *testing.T) {
		nonExistentHash := &[32]byte{}
		copy(nonExistentHash[:], []byte("non-existent-envelope-hash--"))

		request := &Request{
			AppID: testAppID,
			CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
				QueryID:      queryID,
				EnvelopeHash: nonExistentHash,
			},
		}
		d.cancelResendingEncryptedMessage(request)

		select {
		case resp := <-responseCh:
			require.NotNil(t, resp.CancelResendingEncryptedMessageReply)
			require.Equal(t, thin.ThinClientSuccess, resp.CancelResendingEncryptedMessageReply.ErrorCode)
		case <-time.After(time.Second):
			t.Fatal("Expected success response")
		}
	})

	// Test 3: Cancel with nil QueryID
	t.Run("cancel with nil QueryID", func(t *testing.T) {
		request := &Request{
			AppID: testAppID,
			CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
				QueryID:      nil,
				EnvelopeHash: envelopeHash,
			},
		}
		d.cancelResendingEncryptedMessage(request)

		select {
		case resp := <-responseCh:
			require.NotNil(t, resp.CancelResendingEncryptedMessageReply)
			require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.CancelResendingEncryptedMessageReply.ErrorCode)
		case <-time.After(time.Second):
			t.Fatal("Expected error response")
		}
	})

	// Test 4: Cancel with nil EnvelopeHash
	t.Run("cancel with nil EnvelopeHash", func(t *testing.T) {
		request := &Request{
			AppID: testAppID,
			CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
				QueryID:      queryID,
				EnvelopeHash: nil,
			},
		}
		d.cancelResendingEncryptedMessage(request)

		select {
		case resp := <-responseCh:
			require.NotNil(t, resp.CancelResendingEncryptedMessageReply)
			require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.CancelResendingEncryptedMessageReply.ErrorCode)
		case <-time.After(time.Second):
			t.Fatal("Expected error response")
		}
	})

	t.Log("All cancelResendingEncryptedMessage tests passed")
}

// TestCancelResendingDuringARQRetry tests that cancellation works correctly
// when an ARQ message is in the middle of being retried.
func TestCancelResendingDuringARQRetry(t *testing.T) {
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
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap:        make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		replyLock:                 new(sync.Mutex),
	}

	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("test-cancel-rtry"))

	responseCh := make(chan *Response, 10)
	mockConn := &mockIncomingConn{
		appID:      testAppID,
		responseCh: responseCh,
	}

	listener.connsLock.Lock()
	listener.conns[*testAppID] = mockConn.toIncomingConn(listener, logBackend)
	listener.connsLock.Unlock()

	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("retry-query-id--"))

	envelopeHash := &[32]byte{}
	copy(envelopeHash[:], []byte("retry-envelope-hash---------"))

	surbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(surbID[:], []byte("retry-surb-id---"))

	// Pre-populate with a message that has been retried multiple times
	d.replyLock.Lock()
	d.arqSurbIDMap[*surbID] = &ARQMessage{
		AppID:           testAppID,
		QueryID:         queryID,
		EnvelopeHash:    envelopeHash,
		SURBID:          surbID,
		Retransmissions: 50, // Simulating many retries
	}
	d.arqEnvelopeHashMap[*envelopeHash] = surbID
	d.replyLock.Unlock()

	// Cancel the message
	request := &Request{
		AppID: testAppID,
		CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
			QueryID:      queryID,
			EnvelopeHash: envelopeHash,
		},
	}
	d.cancelResendingEncryptedMessage(request)

	// Should receive two responses:
	// 1. StartResendingEncryptedMessageReply with cancellation error
	// 2. CancelResendingEncryptedMessageReply with success

	// First response: StartResendingEncryptedMessageReply with cancellation error
	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.StartResendingEncryptedMessageReply)
		require.Equal(t, thin.ThinClientErrorStartResendingCancelled, resp.StartResendingEncryptedMessageReply.ErrorCode)
		require.Nil(t, resp.StartResendingEncryptedMessageReply.Plaintext)
	case <-time.After(time.Second):
		t.Fatal("Expected StartResendingEncryptedMessageReply with cancellation error")
	}

	// Second response: CancelResendingEncryptedMessageReply with success
	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.CancelResendingEncryptedMessageReply)
		require.Equal(t, thin.ThinClientSuccess, resp.CancelResendingEncryptedMessageReply.ErrorCode)
	case <-time.After(time.Second):
		t.Fatal("Expected CancelResendingEncryptedMessageReply with success")
	}

	// Verify the maps are empty
	d.replyLock.Lock()
	require.Len(t, d.arqSurbIDMap, 0)
	require.Len(t, d.arqEnvelopeHashMap, 0)
	d.replyLock.Unlock()

	// Now try to resend - should not find the message
	require.NotPanics(t, func() {
		d.arqDoResend(surbID)
	}, "arqDoResend should not panic after cancel")

	t.Log("Cancel during ARQ retry test passed")
}
