// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/thin"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

func TestNewKeypairNoConnection(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)

	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("no-conn-keypair0"))

	// Should not panic when connection not found
	d.newKeypair(&Request{
		AppID: unknownAppID,
		NewKeypair: &thin.NewKeypair{
			Seed: make([]byte, 32),
		},
	})
}

func TestEncryptReadNoConnection(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)

	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("no-conn-encread0"))

	d.encryptRead(&Request{
		AppID: unknownAppID,
		EncryptRead: &thin.EncryptRead{
			QueryID: &[thin.QueryIDLength]byte{},
		},
	})
}

func TestEncryptReadNilMessageBoxIndex(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	readCap := createTestReadCap(t)
	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("encread-nil-mbi0"))

	d.encryptRead(&Request{
		AppID: testAppID,
		EncryptRead: &thin.EncryptRead{
			QueryID:         queryID,
			ReadCap:         readCap,
			MessageBoxIndex: nil,
		},
	})

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.EncryptReadReply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.EncryptReadReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestEncryptWriteNoConnection(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)

	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("no-conn-encwrit0"))

	d.encryptWrite(&Request{
		AppID: unknownAppID,
		EncryptWrite: &thin.EncryptWrite{
			QueryID: &[thin.QueryIDLength]byte{},
		},
	})
}

func TestEncryptWriteNilMessageBoxIndex(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("encwrit-nil-mbi0"))

	d.encryptWrite(&Request{
		AppID: testAppID,
		EncryptWrite: &thin.EncryptWrite{
			QueryID:         queryID,
			WriteCap:        writeCap,
			MessageBoxIndex: nil,
		},
	})

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.EncryptWriteReply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.EncryptWriteReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestEncryptWriteNilPlaintext(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	firstIdx := writeCap.GetFirstMessageBoxIndex()
	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("encwrit-nil-pt00"))

	d.encryptWrite(&Request{
		AppID: testAppID,
		EncryptWrite: &thin.EncryptWrite{
			QueryID:         queryID,
			WriteCap:        writeCap,
			MessageBoxIndex: firstIdx,
			Plaintext:       nil,
		},
	})

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.EncryptWriteReply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.EncryptWriteReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestEncryptWriteTombstone(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	firstIdx := writeCap.GetFirstMessageBoxIndex()
	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("encwrit-tombst00"))

	// Empty plaintext = tombstone
	d.encryptWrite(&Request{
		AppID: testAppID,
		EncryptWrite: &thin.EncryptWrite{
			QueryID:         queryID,
			WriteCap:        writeCap,
			MessageBoxIndex: firstIdx,
			Plaintext:       []byte{},
		},
	})

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.EncryptWriteReply)
		require.Equal(t, thin.ThinClientSuccess, resp.EncryptWriteReply.ErrorCode)
		require.NotEmpty(t, resp.EncryptWriteReply.MessageCiphertext)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestEncryptWritePayloadTooLarge(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	firstIdx := writeCap.GetFirstMessageBoxIndex()
	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("encwrit-toolrg00"))

	// Payload larger than MaxPlaintextPayloadLength
	hugePayload := make([]byte, d.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength+100)

	d.encryptWrite(&Request{
		AppID: testAppID,
		EncryptWrite: &thin.EncryptWrite{
			QueryID:         queryID,
			WriteCap:        writeCap,
			MessageBoxIndex: firstIdx,
			Plaintext:       hugePayload,
		},
	})

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.EncryptWriteReply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.EncryptWriteReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSetStreamBufferNilStreamID(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("buffer-nil-sid00"))

	d.setStreamBuffer(&Request{
		AppID: testAppID,
		SetStreamBuffer: &thin.SetStreamBuffer{
			QueryID:  queryID,
			StreamID: nil,
		},
	})

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.SetStreamBufferReply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.SetStreamBufferReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSetStreamBufferNoConnection(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)

	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("no-conn-buffer00"))

	// Should not panic
	d.setStreamBuffer(&Request{
		AppID: unknownAppID,
		SetStreamBuffer: &thin.SetStreamBuffer{
			QueryID:  &[thin.QueryIDLength]byte{},
			StreamID: &[thin.StreamIDLength]byte{},
		},
	})
}

func TestNextMessageBoxIndexNoConnection(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)

	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("no-conn-nextmb00"))

	d.nextMessageBoxIndex(&Request{
		AppID: unknownAppID,
		NextMessageBoxIndex: &thin.NextMessageBoxIndex{
			QueryID: &[thin.QueryIDLength]byte{},
		},
	})
}

func TestCreateEnvelopeFromMessage(t *testing.T) {
	doc := createMockPKIDocument(t)

	msg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0,
		ReadMsg: &pigeonhole.ReplicaRead{
			BoxID: [32]uint8{1, 2, 3},
		},
	}

	env, privKey, err := createEnvelopeFromMessage(msg, doc, true, 0)
	require.NoError(t, err)
	require.NotNil(t, env)
	require.NotNil(t, privKey)
	require.NotEmpty(t, env.Ciphertext)
}

func TestStartResendingEncryptedMessageNoConnection(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)

	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("no-conn-resend00"))

	d.startResendingEncryptedMessage(&Request{
		AppID: unknownAppID,
		StartResendingEncryptedMessage: &thin.StartResendingEncryptedMessage{
			QueryID: &[thin.QueryIDLength]byte{},
		},
	})
}

func TestCancelResendingEncryptedMessageNoConnection(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)

	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("no-conn-cancel00"))

	d.cancelResendingEncryptedMessage(&Request{
		AppID: unknownAppID,
		CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
			QueryID: &[thin.QueryIDLength]byte{},
		},
	})
}

func TestStartResendingCopyCommandNoConnection(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)

	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("no-conn-copycmd0"))

	d.startResendingCopyCommand(&Request{
		AppID: unknownAppID,
		StartResendingCopyCommand: &thin.StartResendingCopyCommand{
			QueryID: &[thin.QueryIDLength]byte{},
		},
	})
}

func TestCancelResendingCopyCommandNoConnection(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)

	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("no-conn-cancopy0"))

	d.cancelResendingCopyCommand(&Request{
		AppID: unknownAppID,
		CancelResendingCopyCommand: &thin.CancelResendingCopyCommand{
			QueryID: &[thin.QueryIDLength]byte{},
		},
	})
}

func TestCancelResendingCopyCommandValidationError(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	// nil QueryID
	d.cancelResendingCopyCommand(&Request{
		AppID: testAppID,
		CancelResendingCopyCommand: &thin.CancelResendingCopyCommand{
			QueryID:      nil,
			WriteCapHash: &[32]byte{},
		},
	})

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.CancelResendingCopyCommandReply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.CancelResendingCopyCommandReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestCancelResendingCopyCommandSuccess(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("cancel-copy-q000"))
	writeCapHash := &[32]byte{}
	copy(writeCapHash[:], []byte("writecap-hash-for-cancel"))

	// Set up an ARQ entry for the copy command
	surbID := &[sphinxConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	require.NoError(t, err)

	origQueryID := &[thin.QueryIDLength]byte{}
	copy(origQueryID[:], []byte("orig-copy-query0"))

	d.replyLock.Lock()
	d.arqSurbIDMap[*surbID] = &ARQMessage{
		MessageType: ARQMessageTypeCopyCommand,
		AppID:       testAppID,
		QueryID:     origQueryID,
		SURBID:      surbID,
	}
	d.arqEnvelopeHashMap[*writeCapHash] = surbID
	d.replyLock.Unlock()

	d.cancelResendingCopyCommand(&Request{
		AppID: testAppID,
		CancelResendingCopyCommand: &thin.CancelResendingCopyCommand{
			QueryID:      queryID,
			WriteCapHash: writeCapHash,
		},
	})

	// Should get cancellation reply for original query + success for cancel query
	responses := drainResponses(responseCh, 2, 5*time.Second)
	require.Len(t, responses, 2)

	// One should be the StartResendingCopyCommandReply (cancellation) and one CancelResendingCopyCommandReply (success)
	var cancelResp, origResp *Response
	for _, r := range responses {
		if r.CancelResendingCopyCommandReply != nil {
			cancelResp = r
		}
		if r.StartResendingCopyCommandReply != nil {
			origResp = r
		}
	}
	require.NotNil(t, cancelResp)
	require.Equal(t, thin.ThinClientSuccess, cancelResp.CancelResendingCopyCommandReply.ErrorCode)
	require.NotNil(t, origResp)
	require.Equal(t, thin.ThinClientErrorStartResendingCancelled, origResp.StartResendingCopyCommandReply.ErrorCode)
}

func TestCreateCourierEnvelopesFromPayloadNoConnection(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)

	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("no-conn-cenvpay0"))

	d.createCourierEnvelopesFromPayload(&Request{
		AppID: unknownAppID,
		CreateCourierEnvelopesFromPayload: &thin.CreateCourierEnvelopesFromPayload{},
	})
}

func TestCreateCourierEnvelopesFromPayloadsNoConnection(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)

	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("no-conn-cenvpys0"))

	d.createCourierEnvelopesFromPayloads(&Request{
		AppID: unknownAppID,
		CreateCourierEnvelopesFromPayloads: &thin.CreateCourierEnvelopesFromPayloads{},
	})
}

func TestCreateCourierEnvelopesFromPayloadsNilStreamID(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("payloads-nilsid0"))

	d.createCourierEnvelopesFromPayloads(&Request{
		AppID: testAppID,
		CreateCourierEnvelopesFromPayloads: &thin.CreateCourierEnvelopesFromPayloads{
			QueryID: queryID,
			Destinations: []thin.DestinationPayload{
				{
					Payload: []byte("data"),
				},
			},
		},
	})

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.CreateCourierEnvelopesFromPayloadsReply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.CreateCourierEnvelopesFromPayloadsReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandlePigeonholeARQReplyNoConnection(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)

	unknownAppID := &[AppIDLength]byte{}
	copy(unknownAppID[:], []byte("no-conn-arqreply"))

	arqMessage := &ARQMessage{
		AppID:   unknownAppID,
		QueryID: &[thin.QueryIDLength]byte{},
	}

	// Should not panic
	d.handlePigeonholeARQReply(arqMessage, &sphinxReply{
		surbID:     &[sphinxConstants.SURBIDLength]byte{},
		ciphertext: []byte("garbage"),
	})
}

// drainResponses reads up to n responses from the channel within the timeout.
func drainResponses(ch chan *Response, n int, timeout time.Duration) []*Response {
	var responses []*Response
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for i := 0; i < n; i++ {
		select {
		case resp := <-ch:
			responses = append(responses, resp)
		case <-timer.C:
			return responses
		}
	}
	return responses
}

func createTestReadCap(t *testing.T) *bacap.ReadCap {
	t.Helper()
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	return writeCap.ReadCap()
}

func TestStartResendingCopyCommandValidationError(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	// nil WriteCap
	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("copy-cmd-nil-wc0"))
	d.startResendingCopyCommand(&Request{
		AppID: testAppID,
		StartResendingCopyCommand: &thin.StartResendingCopyCommand{
			QueryID:  queryID,
			WriteCap: nil,
		},
	})

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.StartResendingCopyCommandReply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.StartResendingCopyCommandReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestCancelResendingEncryptedMessageNilQueryID(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	d.cancelResendingEncryptedMessage(&Request{
		AppID: testAppID,
		CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
			QueryID:      nil,
			EnvelopeHash: &[32]byte{},
		},
	})

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.CancelResendingEncryptedMessageReply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.CancelResendingEncryptedMessageReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestCancelResendingEncryptedMessageNilEnvelopeHash(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("cancel-nil-ehash"))
	d.cancelResendingEncryptedMessage(&Request{
		AppID: testAppID,
		CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
			QueryID:      queryID,
			EnvelopeHash: nil,
		},
	})

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.CancelResendingEncryptedMessageReply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.CancelResendingEncryptedMessageReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestEncryptWriteNoPKIDoc(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	// Clear PKI docs
	d.client.pki.docs = sync.Map{}

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	firstIdx := writeCap.GetFirstMessageBoxIndex()
	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("encwrit-nopki000"))

	d.encryptWrite(&Request{
		AppID: testAppID,
		EncryptWrite: &thin.EncryptWrite{
			QueryID:         queryID,
			WriteCap:        writeCap,
			MessageBoxIndex: firstIdx,
			Plaintext:       []byte("test"),
		},
	})

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.EncryptWriteReply)
		require.Equal(t, thin.ThinClientErrorInternalError, resp.EncryptWriteReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestEncryptReadNoPKIDoc(t *testing.T) {
	d, testAppID, responseCh := setupDaemonWithMockConn(t)

	d.client.pki.docs = sync.Map{}

	readCap := createTestReadCap(t)
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	mbi := writeCap.GetFirstMessageBoxIndex()
	queryID := &[thin.QueryIDLength]byte{}
	copy(queryID[:], []byte("encread-nopki000"))

	d.encryptRead(&Request{
		AppID: testAppID,
		EncryptRead: &thin.EncryptRead{
			QueryID:         queryID,
			ReadCap:         readCap,
			MessageBoxIndex: mbi,
		},
	})

	select {
	case resp := <-responseCh:
		require.NotNil(t, resp.EncryptReadReply)
		require.Equal(t, thin.ThinClientErrorInternalError, resp.EncryptReadReply.ErrorCode)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}
