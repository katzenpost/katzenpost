// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	"github.com/stretchr/testify/require"
)

func newTestThinClientNoConn(t *testing.T) *ThinClient {
	t.Helper()
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	nikeScheme := schemes.ByName("x25519")
	return &ThinClient{
		cfg: &Config{
			SphinxGeometry:     &geo.Geometry{UserForwardPayloadLength: 1000},
			PigeonholeGeometry: pigeonholeGeo.NewGeometry(1000, nikeScheme),
		},
		log:         logBackend.GetLogger("thinclient"),
		logBackend:  logBackend,
		eventSink:   make(chan Event, 10),
		drainAdd:    make(chan chan Event),
		drainRemove: make(chan chan Event),
		pkiDocCache: make(map[uint64]*cpki.Document),
	}
}

func TestFromConfig(t *testing.T) {
	nikeScheme := schemes.ByName("x25519")
	sphinxGeo := &geo.Geometry{UserForwardPayloadLength: 1000}
	pigeonGeo := pigeonholeGeo.NewGeometry(1000, nikeScheme)

	cfg := &config.Config{
		SphinxGeometry:     sphinxGeo,
		PigeonholeGeometry: pigeonGeo,
		ListenNetwork:      "tcp",
		ListenAddress:      "127.0.0.1:12345",
	}

	thinCfg := FromConfig(cfg)
	require.NotNil(t, thinCfg)
	require.Equal(t, sphinxGeo, thinCfg.SphinxGeometry)
	require.Equal(t, pigeonGeo, thinCfg.PigeonholeGeometry)
	require.Equal(t, "tcp", thinCfg.Network)
	require.Equal(t, "127.0.0.1:12345", thinCfg.Address)
}

func TestFromConfigNilSphinxGeometryPanics(t *testing.T) {
	nikeScheme := schemes.ByName("x25519")
	cfg := &config.Config{
		SphinxGeometry:     nil,
		PigeonholeGeometry: pigeonholeGeo.NewGeometry(1000, nikeScheme),
	}
	require.Panics(t, func() {
		FromConfig(cfg)
	})
}

func TestFromConfigNilPigeonholeGeometryPanics(t *testing.T) {
	cfg := &config.Config{
		SphinxGeometry:     &geo.Geometry{UserForwardPayloadLength: 1000},
		PigeonholeGeometry: nil,
	}
	require.Panics(t, func() {
		FromConfig(cfg)
	})
}

func TestLoadFile(t *testing.T) {
	cfg, err := LoadFile("testdata/thinclient.toml")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, "tcp", cfg.Network)
	require.Equal(t, "localhost:64331", cfg.Address)
	require.NotNil(t, cfg.SphinxGeometry)
	require.Equal(t, 2000, cfg.SphinxGeometry.UserForwardPayloadLength)
}

func TestLoadFileNonexistent(t *testing.T) {
	cfg, err := LoadFile("testdata/nonexistent.toml")
	require.Error(t, err)
	require.Nil(t, cfg)
}

func TestLoadFileInvalidTOML(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "invalid.toml")
	err := os.WriteFile(tmpFile, []byte("invalid [[[toml"), 0600)
	require.NoError(t, err)

	cfg, err := LoadFile(tmpFile)
	require.Error(t, err)
	require.Nil(t, cfg)
}

func TestNewThinClient(t *testing.T) {
	nikeScheme := schemes.ByName("x25519")
	cfg := &Config{
		SphinxGeometry:     &geo.Geometry{UserForwardPayloadLength: 1000},
		PigeonholeGeometry: pigeonholeGeo.NewGeometry(1000, nikeScheme),
		Network:            "tcp",
		Address:            "127.0.0.1:12345",
	}
	logging := &config.Logging{
		Level: "DEBUG",
	}

	tc := NewThinClient(cfg, logging)
	require.NotNil(t, tc)
	require.Equal(t, cfg, tc.GetConfig())
	require.NotNil(t, tc.eventSink)
	require.NotNil(t, tc.pkiDocCache)
}

func TestNewThinClientNilSphinxGeometryPanics(t *testing.T) {
	nikeScheme := schemes.ByName("x25519")
	cfg := &Config{
		SphinxGeometry:     nil,
		PigeonholeGeometry: pigeonholeGeo.NewGeometry(1000, nikeScheme),
	}
	require.Panics(t, func() {
		NewThinClient(cfg, &config.Logging{Level: "DEBUG"})
	})
}

func TestNewThinClientNilPigeonholeGeometryPanics(t *testing.T) {
	cfg := &Config{
		SphinxGeometry:     &geo.Geometry{UserForwardPayloadLength: 1000},
		PigeonholeGeometry: nil,
	}
	require.Panics(t, func() {
		NewThinClient(cfg, &config.Logging{Level: "DEBUG"})
	})
}

func TestGetConfig(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	require.Equal(t, tc.cfg, tc.GetConfig())
}

func TestGetLogger(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	logger := tc.GetLogger("test-prefix")
	require.NotNil(t, logger)
}

func TestShutdown(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	// Shutdown should not panic on a fresh client
	tc.Shutdown()
}

func TestNewMessageID(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	id1 := tc.NewMessageID()
	id2 := tc.NewMessageID()
	require.NotNil(t, id1)
	require.NotNil(t, id2)
	require.NotEqual(t, id1[:], id2[:])
	require.Equal(t, MessageIDLength, len(id1))
}

func TestNewQueryID(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	id1 := tc.NewQueryID()
	id2 := tc.NewQueryID()
	require.NotNil(t, id1)
	require.NotNil(t, id2)
	require.NotEqual(t, id1[:], id2[:])
	require.Equal(t, QueryIDLength, len(id1))
}

func TestNewSURBID(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	id1 := tc.NewSURBID()
	id2 := tc.NewSURBID()
	require.NotNil(t, id1)
	require.NotNil(t, id2)
	require.NotEqual(t, id1[:], id2[:])
}

func TestIsConnected(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	require.False(t, tc.IsConnected())

	tc.connMu.Lock()
	tc.isConnected = true
	tc.connMu.Unlock()
	require.True(t, tc.IsConnected())
}

func TestPKIDocument(t *testing.T) {
	tc := newTestThinClientNoConn(t)

	// No document initially
	doc := tc.PKIDocument()
	require.Nil(t, doc)

	// Set a document
	testDoc := &cpki.Document{Epoch: 42}
	tc.pkidocMutex.Lock()
	tc.pkidoc = testDoc
	tc.pkidocMutex.Unlock()

	doc = tc.PKIDocument()
	require.NotNil(t, doc)
	require.Equal(t, uint64(42), doc.Epoch)
}

func TestPKIDocumentForEpochFallback(t *testing.T) {
	tc := newTestThinClientNoConn(t)

	// Set current document but not in cache
	testDoc := &cpki.Document{Epoch: 100}
	tc.pkidocMutex.Lock()
	tc.pkidoc = testDoc
	tc.pkidocMutex.Unlock()

	// Requesting uncached epoch should return current doc as fallback
	doc, err := tc.PKIDocumentForEpoch(999)
	require.NoError(t, err)
	require.Equal(t, uint64(100), doc.Epoch)
}

func TestParsePKIDoc(t *testing.T) {
	tc := newTestThinClientNoConn(t)

	testDoc := &cpki.Document{Epoch: 55}
	payload, err := cbor.Marshal(testDoc)
	require.NoError(t, err)

	doc, err := tc.parsePKIDoc(payload)
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, uint64(55), doc.Epoch)

	// Check it was cached
	cachedDoc, err := tc.PKIDocumentForEpoch(55)
	require.NoError(t, err)
	require.Equal(t, uint64(55), cachedDoc.Epoch)

	// Check current doc was updated
	require.Equal(t, uint64(55), tc.PKIDocument().Epoch)
}

func TestParsePKIDocInvalid(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	doc, err := tc.parsePKIDoc([]byte("not cbor"))
	require.Error(t, err)
	require.Nil(t, doc)
}

func TestParsePKIDocCacheEviction(t *testing.T) {
	tc := newTestThinClientNoConn(t)

	// Add 7 docs to trigger eviction (max is 5)
	for i := uint64(10); i <= 16; i++ {
		testDoc := &cpki.Document{Epoch: i}
		payload, err := cbor.Marshal(testDoc)
		require.NoError(t, err)
		_, err = tc.parsePKIDoc(payload)
		require.NoError(t, err)
	}

	// Old epochs should be evicted
	tc.pkiDocCacheLock.RLock()
	_, exists10 := tc.pkiDocCache[10]
	_, exists16 := tc.pkiDocCache[16]
	tc.pkiDocCacheLock.RUnlock()

	require.False(t, exists10, "epoch 10 should have been evicted")
	require.True(t, exists16, "epoch 16 should still be cached")
}

func TestDispatchSessionTokenReply(t *testing.T) {
	tc := newTestThinClientNoConn(t)
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
	require.True(t, isReply)
	require.True(t, reply.Resumed)
}

func TestDispatchMessageIDGarbageCollected(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	msgID := &[MessageIDLength]byte{1, 2, 3}
	msg := &Response{
		MessageIDGarbageCollected: &MessageIDGarbageCollected{
			MessageID: msgID,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	gc, isGC := event.(*MessageIDGarbageCollected)
	require.True(t, isGC)
	require.Equal(t, msgID, gc.MessageID)
}

func TestDispatchConnectionStatusEvent(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	msg := &Response{
		ConnectionStatusEvent: &ConnectionStatusEvent{
			IsConnected: true,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)
	require.True(t, tc.IsConnected())

	event := <-tc.eventSink
	cs, isCS := event.(*ConnectionStatusEvent)
	require.True(t, isCS)
	require.True(t, cs.IsConnected)
}

func TestDispatchNewPKIDocumentEvent(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	testDoc := &cpki.Document{Epoch: 99}
	payload, err := cbor.Marshal(testDoc)
	require.NoError(t, err)

	msg := &Response{
		NewPKIDocumentEvent: &NewPKIDocumentEvent{
			Payload: payload,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	docEvent, isDoc := event.(*NewDocumentEvent)
	require.True(t, isDoc)
	require.Equal(t, uint64(99), docEvent.Document.Epoch)
}

func TestDispatchNewPKIDocumentEventInvalidPayload(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	msg := &Response{
		NewPKIDocumentEvent: &NewPKIDocumentEvent{
			Payload: []byte("invalid cbor"),
		},
	}
	// Should return true (continue) but log error, not halt
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)
}

func TestDispatchMessageSentEventNonARQ(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	msgID := &[MessageIDLength]byte{1, 2, 3}
	msg := &Response{
		MessageSentEvent: &MessageSentEvent{
			MessageID: msgID,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	sent, isSent := event.(*MessageSentEvent)
	require.True(t, isSent)
	require.Equal(t, msgID, sent.MessageID)
}

func TestDispatchMessageSentEventARQ(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	msgID := [MessageIDLength]byte{4, 5, 6}
	waitCh := make(chan error, 1)
	tc.sentWaitChanMap.Store(msgID, waitCh)

	msg := &Response{
		MessageSentEvent: &MessageSentEvent{
			MessageID: &msgID,
			Err:       "",
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	err := <-waitCh
	require.NoError(t, err)
}

func TestDispatchMessageSentEventARQWithError(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	msgID := [MessageIDLength]byte{7, 8, 9}
	waitCh := make(chan error, 1)
	tc.sentWaitChanMap.Store(msgID, waitCh)

	msg := &Response{
		MessageSentEvent: &MessageSentEvent{
			MessageID: &msgID,
			Err:       "send failed",
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	err := <-waitCh
	require.Error(t, err)
	require.Equal(t, "send failed", err.Error())
}

func TestDispatchMessageSentEventNilMessageID(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	msg := &Response{
		MessageSentEvent: &MessageSentEvent{
			MessageID: nil,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	sent, isSent := event.(*MessageSentEvent)
	require.True(t, isSent)
	require.Nil(t, sent.MessageID)
}

func TestDispatchMessageReplyEventNonARQ(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	msgID := &[MessageIDLength]byte{10, 11, 12}
	msg := &Response{
		MessageReplyEvent: &MessageReplyEvent{
			MessageID: msgID,
			Payload:   []byte("hello"),
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*MessageReplyEvent)
	require.True(t, isReply)
	require.Equal(t, []byte("hello"), reply.Payload)
}

func TestDispatchMessageReplyEventARQ(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	msgID := [MessageIDLength]byte{13, 14, 15}
	waitCh := make(chan *MessageReplyEvent, 1)
	tc.replyWaitChanMap.Store(msgID, waitCh)

	msg := &Response{
		MessageReplyEvent: &MessageReplyEvent{
			MessageID: &msgID,
			Payload:   []byte("arq reply"),
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	reply := <-waitCh
	require.Equal(t, []byte("arq reply"), reply.Payload)
}

func TestDispatchMessageReplyEventNilPayload(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	msg := &Response{
		MessageReplyEvent: &MessageReplyEvent{
			MessageID: &[MessageIDLength]byte{},
			Payload:   nil,
			ErrorCode: ThinClientErrorInternalError,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*MessageReplyEvent)
	require.True(t, isReply)
	require.Nil(t, reply.Payload)
}

func TestDispatchMessageReplyEventNilPayloadNoError(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	msg := &Response{
		MessageReplyEvent: &MessageReplyEvent{
			MessageID: &[MessageIDLength]byte{},
			Payload:   nil,
			ErrorCode: ThinClientSuccess,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)
}

func TestDispatchNewKeypairReply(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	queryID := &[QueryIDLength]byte{1, 2, 3}
	msg := &Response{
		NewKeypairReply: &NewKeypairReply{
			QueryID:   queryID,
			ErrorCode: ThinClientSuccess,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*NewKeypairReply)
	require.True(t, isReply)
	require.Equal(t, queryID, reply.QueryID)
}

func TestDispatchEncryptReadReply(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	queryID := &[QueryIDLength]byte{4, 5, 6}
	msg := &Response{
		EncryptReadReply: &EncryptReadReply{
			QueryID:           queryID,
			MessageCiphertext: []byte("ciphertext"),
			ErrorCode:         ThinClientSuccess,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*EncryptReadReply)
	require.True(t, isReply)
	require.Equal(t, []byte("ciphertext"), reply.MessageCiphertext)
}

func TestDispatchEncryptWriteReply(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	queryID := &[QueryIDLength]byte{7, 8, 9}
	msg := &Response{
		EncryptWriteReply: &EncryptWriteReply{
			QueryID:           queryID,
			MessageCiphertext: []byte("encrypted"),
			ErrorCode:         ThinClientSuccess,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*EncryptWriteReply)
	require.True(t, isReply)
	require.Equal(t, []byte("encrypted"), reply.MessageCiphertext)
}

func TestDispatchStartResendingEncryptedMessageReply(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	queryID := &[QueryIDLength]byte{10, 11, 12}
	msg := &Response{
		StartResendingEncryptedMessageReply: &StartResendingEncryptedMessageReply{
			QueryID:   queryID,
			Plaintext: []byte("decrypted"),
			ErrorCode: ThinClientSuccess,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*StartResendingEncryptedMessageReply)
	require.True(t, isReply)
	require.Equal(t, []byte("decrypted"), reply.Plaintext)
}

func TestDispatchCancelResendingEncryptedMessageReply(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	queryID := &[QueryIDLength]byte{13, 14, 15}
	msg := &Response{
		CancelResendingEncryptedMessageReply: &CancelResendingEncryptedMessageReply{
			QueryID:   queryID,
			ErrorCode: ThinClientSuccess,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*CancelResendingEncryptedMessageReply)
	require.True(t, isReply)
	require.Equal(t, ThinClientSuccess, reply.ErrorCode)
}

func TestDispatchStartResendingCopyCommandReply(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	queryID := &[QueryIDLength]byte{16, 17, 18}
	msg := &Response{
		StartResendingCopyCommandReply: &StartResendingCopyCommandReply{
			QueryID:   queryID,
			ErrorCode: ThinClientSuccess,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*StartResendingCopyCommandReply)
	require.True(t, isReply)
	require.Equal(t, ThinClientSuccess, reply.ErrorCode)
}

func TestDispatchCancelResendingCopyCommandReply(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	queryID := &[QueryIDLength]byte{19, 20, 21}
	msg := &Response{
		CancelResendingCopyCommandReply: &CancelResendingCopyCommandReply{
			QueryID:   queryID,
			ErrorCode: ThinClientSuccess,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*CancelResendingCopyCommandReply)
	require.True(t, isReply)
	require.Equal(t, ThinClientSuccess, reply.ErrorCode)
}

func TestDispatchNextMessageBoxIndexReply(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	queryID := &[QueryIDLength]byte{22, 23, 24}
	msg := &Response{
		NextMessageBoxIndexReply: &NextMessageBoxIndexReply{
			QueryID:   queryID,
			ErrorCode: ThinClientSuccess,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*NextMessageBoxIndexReply)
	require.True(t, isReply)
	require.Equal(t, ThinClientSuccess, reply.ErrorCode)
}

func TestDispatchCreateCourierEnvelopesFromPayloadReply(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	queryID := &[QueryIDLength]byte{25, 26, 27}
	msg := &Response{
		CreateCourierEnvelopesFromPayloadReply: &CreateCourierEnvelopesFromPayloadReply{
			QueryID:   queryID,
			Envelopes: [][]byte{[]byte("env1"), []byte("env2")},
			ErrorCode: ThinClientSuccess,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*CreateCourierEnvelopesFromPayloadReply)
	require.True(t, isReply)
	require.Len(t, reply.Envelopes, 2)
}

func TestDispatchCreateCourierEnvelopesFromPayloadsReply(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	queryID := &[QueryIDLength]byte{28, 29, 30}
	msg := &Response{
		CreateCourierEnvelopesFromPayloadsReply: &CreateCourierEnvelopesFromPayloadsReply{
			QueryID:   queryID,
			Envelopes: [][]byte{[]byte("env1")},
			Buffer:    []byte("buf"),
			ErrorCode: ThinClientSuccess,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*CreateCourierEnvelopesFromPayloadsReply)
	require.True(t, isReply)
	require.Len(t, reply.Envelopes, 1)
	require.Equal(t, []byte("buf"), reply.Buffer)
}

func TestDispatchSetStreamBufferReply(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	queryID := &[QueryIDLength]byte{31, 32, 33}
	msg := &Response{
		SetStreamBufferReply: &SetStreamBufferReply{
			QueryID:   queryID,
			ErrorCode: ThinClientSuccess,
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*SetStreamBufferReply)
	require.True(t, isReply)
	require.Equal(t, ThinClientSuccess, reply.ErrorCode)
}

func TestDispatchDefaultInvalidMessage(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	msg := &Response{} // all nil fields
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	// No event should be sent to eventSink for invalid messages
	select {
	case <-tc.eventSink:
		t.Fatal("no event should be dispatched for invalid message")
	default:
	}
}

func TestGetServicesNoPKIDoc(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	// No PKI doc set, FindServices will panic
	require.Panics(t, func() {
		tc.GetServices("courier")
	})
}

func TestGetServicesNoMatching(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	tc.pkidocMutex.Lock()
	tc.pkidoc = &cpki.Document{
		Epoch:        1,
		ServiceNodes: []*cpki.MixDescriptor{},
	}
	tc.pkidocMutex.Unlock()

	services, err := tc.GetServices("courier")
	require.Error(t, err)
	require.Nil(t, services)
}

func TestGetServicesWithMatching(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	tc.pkidocMutex.Lock()
	tc.pkidoc = &cpki.Document{
		Epoch: 1,
		ServiceNodes: []*cpki.MixDescriptor{
			{
				IdentityKey: []byte("identity-key-1"),
				Kaetzchen: map[string]map[string]interface{}{
					"courier": {"endpoint": "courier-queue-1"},
				},
			},
		},
	}
	tc.pkidocMutex.Unlock()

	services, err := tc.GetServices("courier")
	require.NoError(t, err)
	require.Len(t, services, 1)
	require.Equal(t, []byte("courier-queue-1"), services[0].RecipientQueueID)
}

func TestGetService(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	tc.pkidocMutex.Lock()
	tc.pkidoc = &cpki.Document{
		Epoch: 1,
		ServiceNodes: []*cpki.MixDescriptor{
			{
				IdentityKey: []byte("identity-key-1"),
				Kaetzchen: map[string]map[string]interface{}{
					"echo": {"endpoint": "echo-queue-1"},
				},
			},
			{
				IdentityKey: []byte("identity-key-2"),
				Kaetzchen: map[string]map[string]interface{}{
					"echo": {"endpoint": "echo-queue-2"},
				},
			},
		},
	}
	tc.pkidocMutex.Unlock()

	svc, err := tc.GetService("echo")
	require.NoError(t, err)
	require.NotNil(t, svc)
}

func TestGetServiceNotFound(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	tc.pkidocMutex.Lock()
	tc.pkidoc = &cpki.Document{
		Epoch:        1,
		ServiceNodes: []*cpki.MixDescriptor{},
	}
	tc.pkidocMutex.Unlock()

	svc, err := tc.GetService("nonexistent")
	require.Error(t, err)
	require.Nil(t, svc)
}

func TestCloseWithNilConn(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	tc.conn = nil
	err := tc.Close()
	require.NoError(t, err)
}

func TestDisconnectWithNilConn(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	tc.conn = nil
	err := tc.Disconnect()
	require.NoError(t, err)
}

func TestWriteMessagePayloadTooLarge(t *testing.T) {
	client, _ := net.Pipe()
	tc := newTestThinClientNoConn(t)
	tc.conn = client
	tc.isTCP = true

	// UserForwardPayloadLength is 1000, send 2000 bytes
	bigPayload := make([]byte, 2000)
	req := &Request{
		SendMessage: &SendMessage{
			Payload: bigPayload,
		},
	}
	err := tc.writeMessage(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds maximum allowed size")
}

func TestSendMessageNilSURBID(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	tc.isConnected = true
	err := tc.SendMessage(nil, []byte("test"), &[32]byte{}, []byte("queue"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "surbID cannot be nil")
}

func TestBlockingSendMessageNilContext(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	tc.isConnected = true
	_, err := tc.BlockingSendMessage(nil, []byte("test"), &[32]byte{}, []byte("queue"))
	require.Error(t, err)
	require.Equal(t, errContextCannotBeNil, err)
}

func TestEventSinkWorkerUnbufferedChannelIgnored(t *testing.T) {
	tc := newTestThinClientNoConn(t)

	// Start the eventSinkWorker
	go tc.eventSinkWorker()

	// Try to add an unbuffered channel - should be ignored
	unbuffered := make(chan Event)
	tc.drainAdd <- unbuffered

	// Add a buffered channel - should work
	buffered := make(chan Event, 1)
	tc.drainAdd <- buffered

	// Send an event through eventSink
	tc.eventSink <- &ConnectionStatusEvent{IsConnected: true}

	// Only the buffered channel should receive the event
	event := <-buffered
	cs, ok := event.(*ConnectionStatusEvent)
	require.True(t, ok)
	require.True(t, cs.IsConnected)

	tc.Halt()
}

func TestDispatchHaltChFired(t *testing.T) {
	tc := newTestThinClientNoConn(t)

	// Use a full eventSink so dispatch blocks
	// Fill the eventSink
	for i := 0; i < cap(tc.eventSink); i++ {
		tc.eventSink <- &ConnectionStatusEvent{}
	}

	// Halt the client
	tc.Halt()

	// Dispatching should return false since HaltCh is closed
	msg := &Response{
		NewKeypairReply: &NewKeypairReply{
			QueryID: &[QueryIDLength]byte{1},
		},
	}
	ok := tc.dispatchMessage(msg)
	require.False(t, ok)
}

func TestReadUntilDisconnectHaltCh(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	tc := newTestThinClientNoConn(t)
	tc.conn = client
	tc.isTCP = true

	// Halt immediately so readUntilDisconnect sees HaltCh
	tc.Halt()

	disconnectErr, graceful := tc.readUntilDisconnect()
	// Should return nil error and false when HaltCh fires
	// (the readMessage will fail with closed pipe, and then HaltCh check catches it)
	require.Nil(t, disconnectErr)
	require.False(t, graceful)
}

func TestNewThinClientIsTCP(t *testing.T) {
	nikeScheme := schemes.ByName("x25519")

	tests := []struct {
		network string
		wantTCP bool
	}{
		{"tcp", true},
		{"tcp4", true},
		{"tcp6", true},
		{"TCP", true},
		{"unix", false},
	}

	for _, tt := range tests {
		cfg := &Config{
			SphinxGeometry:     &geo.Geometry{UserForwardPayloadLength: 1000},
			PigeonholeGeometry: pigeonholeGeo.NewGeometry(1000, nikeScheme),
			Network:            tt.network,
			Address:            "localhost:1234",
		}
		tc := NewThinClient(cfg, &config.Logging{Level: "DEBUG"})
		require.Equal(t, tt.wantTCP, tc.isTCP, "network=%s", tt.network)
	}
}

func TestSendMessageOffline(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	tc.isConnected = false
	surbID := tc.NewSURBID()
	err := tc.SendMessage(surbID, []byte("test"), &[32]byte{}, []byte("queue"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot send message in offline mode")
}

func TestSendMessageWithoutReplyOffline(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	tc.isConnected = false
	err := tc.SendMessageWithoutReply([]byte("test"), &[32]byte{}, []byte("queue"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot send message in offline mode")
}

func TestDispatchMessageReplyEventNilMessageID(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	msg := &Response{
		MessageReplyEvent: &MessageReplyEvent{
			MessageID: nil,
			Payload:   []byte("data"),
		},
	}
	ok := tc.dispatchMessage(msg)
	require.True(t, ok)

	event := <-tc.eventSink
	reply, isReply := event.(*MessageReplyEvent)
	require.True(t, isReply)
	require.Nil(t, reply.MessageID)
}

