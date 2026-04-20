// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"errors"
	"net"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	"github.com/stretchr/testify/require"
)

func setupMockDaemon(t *testing.T) (*ThinClient, net.Conn) {
	client, server := net.Pipe()
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	nikeScheme := schemes.ByName("x25519")

	tc := &ThinClient{
		cfg: &Config{
			SphinxGeometry:     &geo.Geometry{UserForwardPayloadLength: 1000},
			PigeonholeGeometry: pigeonholeGeo.NewGeometry(1000, nikeScheme),
		},
		log:         logBackend.GetLogger("thinclient"),
		logBackend:  logBackend,
		isTCP:       true,
		conn:        client,
		eventSink:   make(chan Event, 10),
		drainAdd:    make(chan chan Event),
		drainRemove: make(chan chan Event),
		pkiDocCache: make(map[uint64]*cpki.Document),
	}

	// Start the eventSinkWorker so EventSink()/StopEventSink() work
	go tc.eventSinkWorker()

	// Start a reader goroutine that reads responses from the pipe and dispatches them.
	// This simulates what worker() does in production.
	go func() {
		for {
			msg, err := tc.readMessage()
			if err != nil {
				return
			}
			tc.dispatchMessage(msg)
		}
	}()

	t.Cleanup(func() {
		tc.Halt()
		client.Close()
		server.Close()
	})

	return tc, server
}

func TestErrorCodeToSentinel(t *testing.T) {
	tests := []struct {
		name      string
		code      uint8
		expected  error
		isNil     bool
		checkType bool
	}{
		{"Success", ThinClientSuccess, nil, true, false},
		{"BoxIDNotFound", 1, ErrBoxIDNotFound, false, true},
		{"InvalidBoxID", 2, ErrInvalidBoxID, false, true},
		{"InvalidSignature", 3, ErrInvalidSignature, false, true},
		{"DatabaseFailure", 4, ErrDatabaseFailure, false, true},
		{"InvalidPayload", 5, ErrInvalidPayload, false, true},
		{"StorageFull", 6, ErrStorageFull, false, true},
		{"ReplicaInternalError", 7, ErrReplicaInternalError, false, true},
		{"InvalidEpoch", 8, ErrInvalidEpoch, false, true},
		{"ReplicationFailed", 9, ErrReplicationFailed, false, true},
		{"BoxAlreadyExists", 10, ErrBoxAlreadyExists, false, true},
		{"Tombstone", 11, ErrTombstone, false, true},
		{"MKEMDecryptionFailed", ThinClientErrorMKEMDecryptionFailed, ErrMKEMDecryptionFailed, false, true},
		{"BACAPDecryptionFailed", ThinClientErrorBACAPDecryptionFailed, ErrBACAPDecryptionFailed, false, true},
		{"StartResendingCancelled", ThinClientErrorStartResendingCancelled, ErrStartResendingCancelled, false, true},
		{"InvalidTombstoneSig", ThinClientErrorInvalidTombstoneSig, ErrInvalidTombstoneSignature, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errorCodeToSentinel(tt.code)
			if tt.isNil {
				require.NoError(t, err)
			} else if tt.checkType {
				require.True(t, errors.Is(err, tt.expected), "expected %v, got %v", tt.expected, err)
			}
		})
	}

	// Test unknown/default code
	t.Run("UnknownCode", func(t *testing.T) {
		err := errorCodeToSentinel(200)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Unknown thin client error code: 200")
	})
}

func TestHashIdentityKey(t *testing.T) {
	key := []byte("test-identity-key")
	result := hashIdentityKey(key)
	expected := hash.Sum256(key)
	require.Equal(t, expected, result)

	// Deterministic
	result2 := hashIdentityKey(key)
	require.Equal(t, result, result2)

	// Different key gives different hash
	result3 := hashIdentityKey([]byte("different-key"))
	require.NotEqual(t, result, result3)
}



func newTestWriteCap(t *testing.T) *bacap.WriteCap {
	t.Helper()
	wc, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	return wc
}

func newTestReadCap(t *testing.T) *bacap.ReadCap {
	t.Helper()
	wc := newTestWriteCap(t)
	return wc.ReadCap()
}

func newTestMessageBoxIndex(t *testing.T) *bacap.MessageBoxIndex {
	t.Helper()
	idx, err := bacap.NewMessageBoxIndex(rand.Reader)
	require.NoError(t, err)
	return idx
}

func setupTestThinClient(t *testing.T) *ThinClient {
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

func TestNewKeypairSeedValidation(t *testing.T) {
	tc, server := setupMockDaemon(t)
	_ = server

	// Seed too short
	_, _, _, err := tc.NewKeypair([]byte("short"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "seed must be exactly 32 bytes")

	// Seed too long
	_, _, _, err = tc.NewKeypair(make([]byte, 64))
	require.Error(t, err)
	require.Contains(t, err.Error(), "seed must be exactly 32 bytes")
}

func TestNewKeypairSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)

	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	go func() {
		// Read the request from the pipe
		req, err := readRequest(server)
		if err != nil {
			return
		}
		require.NotNil(t, req.NewKeypair)

		// Send reply with matching QueryID
		// Note: WriteCap/ReadCap/FirstMessageIndex are nil here because
		// empty BACAP types can't be CBOR-marshaled without proper initialization.
		// The test validates request/response flow, not BACAP crypto.
		sendResponse(t, server, &Response{
			NewKeypairReply: &NewKeypairReply{
				QueryID:   req.NewKeypair.QueryID,
				ErrorCode: ThinClientSuccess,
			},
		})
	}()

	writeCap, readCap, firstIndex, err := tc.NewKeypair(seed)
	require.NoError(t, err)
	// WriteCap/ReadCap/FirstMessageIndex are nil in mock response
	_ = writeCap
	_ = readCap
	_ = firstIndex
}

func TestNewKeypairError(t *testing.T) {
	tc, server := setupMockDaemon(t)

	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		sendResponse(t, server, &Response{
			NewKeypairReply: &NewKeypairReply{
				QueryID:   req.NewKeypair.QueryID,
				ErrorCode: ThinClientErrorInternalError,
			},
		})
	}()

	_, _, _, err = tc.NewKeypair(seed)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Internal error")
}

func TestNewKeypairIgnoresMismatchedQueryID(t *testing.T) {
	tc, server := setupMockDaemon(t)

	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		// Send reply with wrong QueryID first
		wrongQueryID := &[QueryIDLength]byte{0xff, 0xff, 0xff}
		sendResponse(t, server, &Response{
			NewKeypairReply: &NewKeypairReply{
				QueryID:   wrongQueryID,
				ErrorCode: ThinClientSuccess,
			},
		})

		// Send reply with nil QueryID
		sendResponse(t, server, &Response{
			NewKeypairReply: &NewKeypairReply{
				QueryID:   nil,
				ErrorCode: ThinClientSuccess,
			},
		})

		// Send correct reply
		sendResponse(t, server, &Response{
			NewKeypairReply: &NewKeypairReply{
				QueryID:   req.NewKeypair.QueryID,
				ErrorCode: ThinClientSuccess,
			},
		})
	}()

	_, _, _, err = tc.NewKeypair(seed)
	require.NoError(t, err)
}

func TestEncryptReadNilArgs(t *testing.T) {
	tc, _ := setupMockDaemon(t)

	_, _, _, _, err := tc.EncryptRead(nil, newTestMessageBoxIndex(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "readCap cannot be nil")

	_, _, _, _, err = tc.EncryptRead(newTestReadCap(t), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "messageBoxIndex cannot be nil")
}

func TestEncryptReadSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)

	expectedNextIndex := newTestMessageBoxIndex(t)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		require.NotNil(t, req.EncryptRead)

		envHash := &[32]byte{1, 2, 3}
		sendResponse(t, server, &Response{
			EncryptReadReply: &EncryptReadReply{
				QueryID:             req.EncryptRead.QueryID,
				MessageCiphertext:   []byte("ciphertext"),
				EnvelopeDescriptor:  []byte("descriptor"),
				EnvelopeHash:        envHash,
				NextMessageBoxIndex: expectedNextIndex,
				ErrorCode:           ThinClientSuccess,
			},
		})
	}()

	ciphertext, descriptor, envHash, nextIndex, err := tc.EncryptRead(newTestReadCap(t), newTestMessageBoxIndex(t))
	require.NoError(t, err)
	require.Equal(t, []byte("ciphertext"), ciphertext)
	require.Equal(t, []byte("descriptor"), descriptor)
	require.NotNil(t, envHash)
	require.NotNil(t, nextIndex)
	require.Equal(t, expectedNextIndex.Idx64, nextIndex.Idx64)
}

func TestEncryptReadError(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		sendResponse(t, server, &Response{
			EncryptReadReply: &EncryptReadReply{
				QueryID:   req.EncryptRead.QueryID,
				ErrorCode: ThinClientErrorInternalError,
			},
		})
	}()

	_, _, _, _, err := tc.EncryptRead(newTestReadCap(t), newTestMessageBoxIndex(t))
	require.Error(t, err)
}

func TestEncryptWriteNilArgs(t *testing.T) {
	tc, _ := setupMockDaemon(t)

	_, _, _, _, err := tc.EncryptWrite([]byte("hello"), nil, newTestMessageBoxIndex(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "writeCap cannot be nil")

	_, _, _, _, err = tc.EncryptWrite([]byte("hello"), newTestWriteCap(t), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "messageBoxIndex cannot be nil")
}

func TestEncryptWriteSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)

	expectedNextIndex := newTestMessageBoxIndex(t)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		require.NotNil(t, req.EncryptWrite)

		envHash := &[32]byte{4, 5, 6}
		sendResponse(t, server, &Response{
			EncryptWriteReply: &EncryptWriteReply{
				QueryID:             req.EncryptWrite.QueryID,
				MessageCiphertext:   []byte("encrypted"),
				EnvelopeDescriptor:  []byte("desc"),
				EnvelopeHash:        envHash,
				NextMessageBoxIndex: expectedNextIndex,
				ErrorCode:           ThinClientSuccess,
			},
		})
	}()

	ciphertext, descriptor, envHash, nextIndex, err := tc.EncryptWrite([]byte("hello"), newTestWriteCap(t), newTestMessageBoxIndex(t))
	require.NoError(t, err)
	require.Equal(t, []byte("encrypted"), ciphertext)
	require.Equal(t, []byte("desc"), descriptor)
	require.NotNil(t, envHash)
	require.NotNil(t, nextIndex)
	require.Equal(t, expectedNextIndex.Idx64, nextIndex.Idx64)
}

func TestStartResendingEncryptedMessageNilEnvelopeHash(t *testing.T) {
	tc, _ := setupMockDaemon(t)

	_, err := tc.StartResendingEncryptedMessage(nil, nil, nil, nil, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "envelopeHash cannot be nil")
}

func TestStartResendingEncryptedMessageWriteSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)

	envHash := &[32]byte{7, 8, 9}
	courierHash := &[32]byte{10, 11, 12}

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		require.NotNil(t, req.StartResendingEncryptedMessage)

		sendResponse(t, server, &Response{
			StartResendingEncryptedMessageReply: &StartResendingEncryptedMessageReply{
				QueryID:             req.StartResendingEncryptedMessage.QueryID,
				Plaintext:           nil,
				ErrorCode:           ThinClientSuccess,
				CourierIdentityHash: courierHash,
				CourierQueueID:      []byte("queue1"),
			},
		})
	}()

	result, err := tc.StartResendingEncryptedMessage(
		nil,                 // readCap (nil = write)
		newTestWriteCap(t),   // writeCap
		nil,                 // nextMessageIndex
		nil,                 // replyIndex
		[]byte("desc"),      // envelopeDescriptor
		[]byte("cipher"),    // messageCiphertext
		envHash,             // envelopeHash
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, courierHash, result.CourierIdentityHash)
	require.Equal(t, []byte("queue1"), result.CourierQueueID)
}

func TestStartResendingEncryptedMessageReadSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)

	envHash := &[32]byte{13, 14, 15}

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		sendResponse(t, server, &Response{
			StartResendingEncryptedMessageReply: &StartResendingEncryptedMessageReply{
				QueryID:   req.StartResendingEncryptedMessage.QueryID,
				Plaintext: []byte("decrypted message"),
				ErrorCode: ThinClientSuccess,
			},
		})
	}()

	replyIndex := uint8(0)
	result, err := tc.StartResendingEncryptedMessage(
		newTestReadCap(t),    // readCap (non-nil = read)
		nil,                 // writeCap
		[]byte("nextidx"),   // nextMessageIndex
		&replyIndex,         // replyIndex
		[]byte("desc"),      // envelopeDescriptor
		[]byte("cipher"),    // messageCiphertext
		envHash,             // envelopeHash
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, []byte("decrypted message"), result.Plaintext)
}

func TestStartResendingEncryptedMessageErrorCode(t *testing.T) {
	tc, server := setupMockDaemon(t)

	envHash := &[32]byte{16, 17, 18}

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		sendResponse(t, server, &Response{
			StartResendingEncryptedMessageReply: &StartResendingEncryptedMessageReply{
				QueryID:   req.StartResendingEncryptedMessage.QueryID,
				ErrorCode: 1, // BoxIDNotFound
			},
		})
	}()

	_, err := tc.StartResendingEncryptedMessage(
		newTestReadCap(t), nil, nil, nil, nil, nil, envHash,
	)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrBoxIDNotFound))
}

func TestStartResendingEncryptedMessageNoRetry(t *testing.T) {
	tc, server := setupMockDaemon(t)

	envHash := &[32]byte{19, 20, 21}

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		require.True(t, req.StartResendingEncryptedMessage.NoRetryOnBoxIDNotFound)

		sendResponse(t, server, &Response{
			StartResendingEncryptedMessageReply: &StartResendingEncryptedMessageReply{
				QueryID:   req.StartResendingEncryptedMessage.QueryID,
				ErrorCode: ThinClientSuccess,
				Plaintext: []byte("data"),
			},
		})
	}()

	result, err := tc.StartResendingEncryptedMessageNoRetry(
		newTestReadCap(t), nil, nil, nil, nil, nil, envHash,
	)
	require.NoError(t, err)
	require.Equal(t, []byte("data"), result.Plaintext)
}

func TestStartResendingEncryptedMessageNoRetryNilEnvelopeHash(t *testing.T) {
	tc, _ := setupMockDaemon(t)
	_, err := tc.StartResendingEncryptedMessageNoRetry(nil, nil, nil, nil, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "envelopeHash cannot be nil")
}

func TestStartResendingEncryptedMessageReturnBoxExists(t *testing.T) {
	tc, server := setupMockDaemon(t)

	envHash := &[32]byte{22, 23, 24}

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		require.True(t, req.StartResendingEncryptedMessage.NoIdempotentBoxAlreadyExists)

		sendResponse(t, server, &Response{
			StartResendingEncryptedMessageReply: &StartResendingEncryptedMessageReply{
				QueryID:   req.StartResendingEncryptedMessage.QueryID,
				ErrorCode: 10, // BoxAlreadyExists
			},
		})
	}()

	_, err := tc.StartResendingEncryptedMessageReturnBoxExists(
		nil, newTestWriteCap(t), nil, nil, nil, nil, envHash,
	)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrBoxAlreadyExists))
}

func TestStartResendingEncryptedMessageReturnBoxExistsNilEnvelopeHash(t *testing.T) {
	tc, _ := setupMockDaemon(t)
	_, err := tc.StartResendingEncryptedMessageReturnBoxExists(nil, nil, nil, nil, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "envelopeHash cannot be nil")
}

func TestCancelResendingEncryptedMessageNilHash(t *testing.T) {
	tc, _ := setupMockDaemon(t)
	err := tc.CancelResendingEncryptedMessage(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "envelopeHash cannot be nil")
}

func TestCancelResendingEncryptedMessageOffline(t *testing.T) {
	tc, _ := setupMockDaemon(t)
	tc.isConnected = false
	envHash := &[32]byte{1, 2, 3}

	// Store something in inFlightResends to verify it gets removed
	tc.inFlightResends.Store(*envHash, &Request{})

	err := tc.CancelResendingEncryptedMessage(envHash)
	require.NoError(t, err)

	// Verify it was removed from tracking
	_, loaded := tc.inFlightResends.Load(*envHash)
	require.False(t, loaded)
}

func TestCancelResendingEncryptedMessageSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)
	tc.isConnected = true

	envHash := &[32]byte{25, 26, 27}

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		require.NotNil(t, req.CancelResendingEncryptedMessage)

		sendResponse(t, server, &Response{
			CancelResendingEncryptedMessageReply: &CancelResendingEncryptedMessageReply{
				QueryID:   req.CancelResendingEncryptedMessage.QueryID,
				ErrorCode: ThinClientSuccess,
			},
		})
	}()

	err := tc.CancelResendingEncryptedMessage(envHash)
	require.NoError(t, err)
}

func TestStartResendingCopyCommandNilWriteCap(t *testing.T) {
	tc, _ := setupMockDaemon(t)
	err := tc.StartResendingCopyCommand(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "writeCap cannot be nil")
}

func TestStartResendingCopyCommandSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		require.NotNil(t, req.StartResendingCopyCommand)

		sendResponse(t, server, &Response{
			StartResendingCopyCommandReply: &StartResendingCopyCommandReply{
				QueryID:   req.StartResendingCopyCommand.QueryID,
				ErrorCode: ThinClientSuccess,
			},
		})
	}()

	err := tc.StartResendingCopyCommand(newTestWriteCap(t))
	require.NoError(t, err)
}

func TestStartResendingCopyCommandError(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		sendResponse(t, server, &Response{
			StartResendingCopyCommandReply: &StartResendingCopyCommandReply{
				QueryID:   req.StartResendingCopyCommand.QueryID,
				ErrorCode: ThinClientErrorCopyCommandFailed,
			},
		})
	}()

	err := tc.StartResendingCopyCommand(newTestWriteCap(t))
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrCopyCommandFailed),
		"ErrorCode=ThinClientErrorCopyCommandFailed must map to ErrCopyCommandFailed via the thin-client-namespace interpreter, not to a replica sentinel")
}

func TestStartResendingCopyCommandWithCourierNilArgs(t *testing.T) {
	tc, _ := setupMockDaemon(t)

	err := tc.StartResendingCopyCommandWithCourier(nil, &[32]byte{}, []byte("q"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "writeCap cannot be nil")

	err = tc.StartResendingCopyCommandWithCourier(newTestWriteCap(t), nil, []byte("q"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "courierIdentityHash cannot be nil")

	err = tc.StartResendingCopyCommandWithCourier(newTestWriteCap(t), &[32]byte{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "courierQueueID cannot be empty")

	err = tc.StartResendingCopyCommandWithCourier(newTestWriteCap(t), &[32]byte{}, []byte{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "courierQueueID cannot be empty")
}

func TestStartResendingCopyCommandWithCourierSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)

	courierHash := &[32]byte{1, 2, 3}

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		require.NotNil(t, req.StartResendingCopyCommand)
		require.Equal(t, courierHash[:], req.StartResendingCopyCommand.CourierIdentityHash[:])

		sendResponse(t, server, &Response{
			StartResendingCopyCommandReply: &StartResendingCopyCommandReply{
				QueryID:   req.StartResendingCopyCommand.QueryID,
				ErrorCode: ThinClientSuccess,
			},
		})
	}()

	err := tc.StartResendingCopyCommandWithCourier(newTestWriteCap(t), courierHash, []byte("queue1"))
	require.NoError(t, err)
}

func TestCancelResendingCopyCommandNilHash(t *testing.T) {
	tc, _ := setupMockDaemon(t)
	err := tc.CancelResendingCopyCommand(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "writeCapHash cannot be nil")
}

func TestCancelResendingCopyCommandOffline(t *testing.T) {
	tc, _ := setupMockDaemon(t)
	tc.isConnected = false
	hash := &[32]byte{1, 2, 3}
	err := tc.CancelResendingCopyCommand(hash)
	require.NoError(t, err)
}

func TestCancelResendingCopyCommandSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)
	tc.isConnected = true

	hash := &[32]byte{28, 29, 30}

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		require.NotNil(t, req.CancelResendingCopyCommand)

		sendResponse(t, server, &Response{
			CancelResendingCopyCommandReply: &CancelResendingCopyCommandReply{
				QueryID:   req.CancelResendingCopyCommand.QueryID,
				ErrorCode: ThinClientSuccess,
			},
		})
	}()

	err := tc.CancelResendingCopyCommand(hash)
	require.NoError(t, err)
}

func TestNextMessageBoxIndexNil(t *testing.T) {
	tc, _ := setupMockDaemon(t)
	_, err := tc.NextMessageBoxIndex(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "messageBoxIndex cannot be nil")
}

func TestNextMessageBoxIndexSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		require.NotNil(t, req.NextMessageBoxIndex)

		sendResponse(t, server, &Response{
			NextMessageBoxIndexReply: &NextMessageBoxIndexReply{
				QueryID:             req.NextMessageBoxIndex.QueryID,
				NextMessageBoxIndex: newTestMessageBoxIndex(t),
				ErrorCode:           ThinClientSuccess,
			},
		})
	}()

	nextIndex, err := tc.NextMessageBoxIndex(newTestMessageBoxIndex(t))
	require.NoError(t, err)
	require.NotNil(t, nextIndex)
}

func TestNextMessageBoxIndexError(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		sendResponse(t, server, &Response{
			NextMessageBoxIndexReply: &NextMessageBoxIndexReply{
				QueryID:   req.NextMessageBoxIndex.QueryID,
				ErrorCode: ThinClientErrorInternalError,
			},
		})
	}()

	_, err := tc.NextMessageBoxIndex(newTestMessageBoxIndex(t))
	require.Error(t, err)
}

func TestCreateCourierEnvelopesFromPayloadNilArgs(t *testing.T) {
	tc, _ := setupMockDaemon(t)

	_, _, err := tc.CreateCourierEnvelopesFromPayload([]byte("data"), nil, newTestMessageBoxIndex(t), true, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "destWriteCap cannot be nil")

	_, _, err = tc.CreateCourierEnvelopesFromPayload([]byte("data"), newTestWriteCap(t), nil, true, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "destStartIndex cannot be nil")
}

func TestCreateCourierEnvelopesFromPayloadSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		require.NotNil(t, req.CreateCourierEnvelopesFromPayload)

		sendResponse(t, server, &Response{
			CreateCourierEnvelopesFromPayloadReply: &CreateCourierEnvelopesFromPayloadReply{
				QueryID:       req.CreateCourierEnvelopesFromPayload.QueryID,
				Envelopes:     [][]byte{[]byte("env1"), []byte("env2")},
				NextDestIndex: newTestMessageBoxIndex(t),
				ErrorCode:     ThinClientSuccess,
			},
		})
	}()

	envelopes, nextIdx, err := tc.CreateCourierEnvelopesFromPayload(
		[]byte("data"), newTestWriteCap(t), newTestMessageBoxIndex(t), true, true)
	require.NoError(t, err)
	require.Len(t, envelopes, 2)
	require.NotNil(t, nextIdx)
}

func TestCreateCourierEnvelopesFromMultiPayloadNilArgs(t *testing.T) {
	tc, _ := setupMockDaemon(t)

	_, err := tc.CreateCourierEnvelopesFromMultiPayload(nil, true, false, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "destinations cannot be empty")

	_, err = tc.CreateCourierEnvelopesFromMultiPayload([]DestinationPayload{}, true, false, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "destinations cannot be empty")
}

func TestCreateCourierEnvelopesFromMultiPayloadSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		require.NotNil(t, req.CreateCourierEnvelopesFromPayloads)

		sendResponse(t, server, &Response{
			CreateCourierEnvelopesFromPayloadsReply: &CreateCourierEnvelopesFromPayloadsReply{
				QueryID:         req.CreateCourierEnvelopesFromPayloads.QueryID,
				Envelopes:       [][]byte{[]byte("env1")},
				Buffer:          []byte("buffer-state"),
				NextDestIndices: []*bacap.MessageBoxIndex{{}},
				ErrorCode:       ThinClientSuccess,
			},
		})
	}()

	result, err := tc.CreateCourierEnvelopesFromMultiPayload(
		[]DestinationPayload{{Payload: []byte("data"), WriteCap: newTestWriteCap(t), StartIndex: newTestMessageBoxIndex(t)}},
		true, true, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Envelopes, 1)
	require.Equal(t, []byte("buffer-state"), result.Buffer)
	require.Len(t, result.NextDestIndices, 1)
}

func TestGetAllCouriers(t *testing.T) {
	tc := setupTestThinClient(t)
	tc.pkidocMutex.Lock()
	tc.pkidoc = &cpki.Document{
		Epoch: 1,
		ServiceNodes: []*cpki.MixDescriptor{
			{
				IdentityKey: []byte("courier-identity-1"),
				Kaetzchen: map[string]map[string]interface{}{
					"courier": {"endpoint": "courier-queue-1"},
				},
			},
			{
				IdentityKey: []byte("courier-identity-2"),
				Kaetzchen: map[string]map[string]interface{}{
					"courier": {"endpoint": "courier-queue-2"},
				},
			},
		},
	}
	tc.pkidocMutex.Unlock()

	couriers, err := tc.GetAllCouriers()
	require.NoError(t, err)
	require.Len(t, couriers, 2)

	expectedHash1 := hash.Sum256([]byte("courier-identity-1"))
	require.Equal(t, expectedHash1, *couriers[0].IdentityHash)
	require.Equal(t, []byte("courier-queue-1"), couriers[0].QueueID)
}

func TestGetAllCouriersNoCouriers(t *testing.T) {
	tc := setupTestThinClient(t)
	tc.pkidocMutex.Lock()
	tc.pkidoc = &cpki.Document{
		Epoch:        1,
		ServiceNodes: []*cpki.MixDescriptor{},
	}
	tc.pkidocMutex.Unlock()

	couriers, err := tc.GetAllCouriers()
	require.Error(t, err)
	require.Nil(t, couriers)
}

func TestGetDistinctCouriers(t *testing.T) {
	tc := setupTestThinClient(t)
	tc.pkidocMutex.Lock()
	tc.pkidoc = &cpki.Document{
		Epoch: 1,
		ServiceNodes: []*cpki.MixDescriptor{
			{
				IdentityKey: []byte("c1"),
				Kaetzchen: map[string]map[string]interface{}{
					"courier": {"endpoint": "q1"},
				},
			},
			{
				IdentityKey: []byte("c2"),
				Kaetzchen: map[string]map[string]interface{}{
					"courier": {"endpoint": "q2"},
				},
			},
			{
				IdentityKey: []byte("c3"),
				Kaetzchen: map[string]map[string]interface{}{
					"courier": {"endpoint": "q3"},
				},
			},
		},
	}
	tc.pkidocMutex.Unlock()

	couriers, err := tc.GetDistinctCouriers(2)
	require.NoError(t, err)
	require.Len(t, couriers, 2)

	// Verify they are distinct
	require.NotEqual(t, couriers[0].IdentityHash, couriers[1].IdentityHash)
}

func TestGetDistinctCouriersNotEnough(t *testing.T) {
	tc := setupTestThinClient(t)
	tc.pkidocMutex.Lock()
	tc.pkidoc = &cpki.Document{
		Epoch: 1,
		ServiceNodes: []*cpki.MixDescriptor{
			{
				IdentityKey: []byte("c1"),
				Kaetzchen: map[string]map[string]interface{}{
					"courier": {"endpoint": "q1"},
				},
			},
		},
	}
	tc.pkidocMutex.Unlock()

	_, err := tc.GetDistinctCouriers(5)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not enough couriers available")
}

func TestTombstoneRangeNilArgs(t *testing.T) {
	tc, _ := setupMockDaemon(t)

	_, err := tc.TombstoneRange(nil, newTestMessageBoxIndex(t), 5)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil writeCap")

	_, err = tc.TombstoneRange(newTestWriteCap(t), nil, 5)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil start index")
}

func TestTombstoneRangeZeroCount(t *testing.T) {
	tc, _ := setupMockDaemon(t)

	start := newTestMessageBoxIndex(t)
	result, err := tc.TombstoneRange(newTestWriteCap(t), start, 0)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Nil(t, result.Envelopes)
	require.Equal(t, start, result.Next)
}

func TestCBORRoundTrip(t *testing.T) {
	// Verify that Request/Response can be serialized and deserialized correctly
	queryID := &[QueryIDLength]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	req := &Request{
		NewKeypair: &NewKeypair{
			QueryID: queryID,
			Seed:    make([]byte, 32),
		},
	}

	data, err := cbor.Marshal(req)
	require.NoError(t, err)

	decoded := &Request{}
	err = cbor.Unmarshal(data, decoded)
	require.NoError(t, err)
	require.NotNil(t, decoded.NewKeypair)
	require.Equal(t, queryID[:], decoded.NewKeypair.QueryID[:])
}

func TestCancelResendingCopyCommandError(t *testing.T) {
	tc, server := setupMockDaemon(t)
	tc.isConnected = true

	hash := &[32]byte{31, 32, 33}

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		sendResponse(t, server, &Response{
			CancelResendingCopyCommandReply: &CancelResendingCopyCommandReply{
				QueryID:   req.CancelResendingCopyCommand.QueryID,
				ErrorCode: ThinClientErrorInternalError,
			},
		})
	}()

	err := tc.CancelResendingCopyCommand(hash)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Internal error")
}

func TestCancelResendingEncryptedMessageError(t *testing.T) {
	tc, server := setupMockDaemon(t)
	tc.isConnected = true

	envHash := &[32]byte{34, 35, 36}

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		sendResponse(t, server, &Response{
			CancelResendingEncryptedMessageReply: &CancelResendingEncryptedMessageReply{
				QueryID:   req.CancelResendingEncryptedMessage.QueryID,
				ErrorCode: ThinClientErrorInternalError,
			},
		})
	}()

	err := tc.CancelResendingEncryptedMessage(envHash)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Internal error")
}

func TestCreateCourierEnvelopesFromPayloadError(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		sendResponse(t, server, &Response{
			CreateCourierEnvelopesFromPayloadReply: &CreateCourierEnvelopesFromPayloadReply{
				QueryID:   req.CreateCourierEnvelopesFromPayload.QueryID,
				ErrorCode: ThinClientErrorInternalError,
			},
		})
	}()

	_, _, err := tc.CreateCourierEnvelopesFromPayload(
		[]byte("data"), newTestWriteCap(t), newTestMessageBoxIndex(t), true, true)
	require.Error(t, err)
}

func TestCreateCourierEnvelopesFromMultiPayloadError(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		sendResponse(t, server, &Response{
			CreateCourierEnvelopesFromPayloadsReply: &CreateCourierEnvelopesFromPayloadsReply{
				QueryID:   req.CreateCourierEnvelopesFromPayloads.QueryID,
				ErrorCode: ThinClientErrorInternalError,
			},
		})
	}()

	_, err := tc.CreateCourierEnvelopesFromMultiPayload(
		[]DestinationPayload{{Payload: []byte("x"), WriteCap: newTestWriteCap(t), StartIndex: newTestMessageBoxIndex(t)}},
		true, true, nil,
	)
	require.Error(t, err)
}

func TestEncryptWriteError(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		sendResponse(t, server, &Response{
			EncryptWriteReply: &EncryptWriteReply{
				QueryID:   req.EncryptWrite.QueryID,
				ErrorCode: ThinClientErrorInternalError,
			},
		})
	}()

	_, _, _, _, err := tc.EncryptWrite([]byte("hello"), newTestWriteCap(t), newTestMessageBoxIndex(t))
	require.Error(t, err)
}

func TestNewKeypairConnectionStatusDuringWait(t *testing.T) {
	tc, server := setupMockDaemon(t)

	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		// First send a connection status event (should be ignored by NewKeypair)
		sendResponse(t, server, &Response{
			ConnectionStatusEvent: &ConnectionStatusEvent{
				IsConnected: true,
			},
		})

		// Then send the actual reply
		sendResponse(t, server, &Response{
			NewKeypairReply: &NewKeypairReply{
				QueryID:   req.NewKeypair.QueryID,
				ErrorCode: ThinClientSuccess,
			},
		})
	}()

	_, _, _, err = tc.NewKeypair(seed)
	require.NoError(t, err)
}

func TestInFlightResendTracking(t *testing.T) {
	tc, server := setupMockDaemon(t)

	envHash := &[32]byte{50, 51, 52}

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}

		// Before replying, verify the request is tracked
		_, loaded := tc.inFlightResends.Load(*envHash)
		require.True(t, loaded, "request should be tracked as in-flight")

		sendResponse(t, server, &Response{
			StartResendingEncryptedMessageReply: &StartResendingEncryptedMessageReply{
				QueryID:   req.StartResendingEncryptedMessage.QueryID,
				ErrorCode: ThinClientSuccess,
			},
		})
	}()

	_, err := tc.StartResendingEncryptedMessage(
		nil, newTestWriteCap(t), nil, nil, nil, nil, envHash,
	)
	require.NoError(t, err)

	// After completion, it should be removed from tracking
	_, loaded := tc.inFlightResends.Load(*envHash)
	require.False(t, loaded, "request should be removed from in-flight tracking after completion")
}
