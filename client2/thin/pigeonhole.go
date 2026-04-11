// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"
)

// StartResendingResult is returned by StartResendingEncryptedMessage and its variants.
type StartResendingResult struct {
	// Plaintext is the decrypted message for read operations, or empty for writes.
	Plaintext []byte

	// CourierIdentityHash is the 32-byte hash of the identity key of the courier that
	// handled this message. Callers can watch PKI document updates for this courier
	// disappearing from consensus and cancel+re-encrypt if needed.
	CourierIdentityHash *[32]byte

	// CourierQueueID is the queue ID of the courier that handled this message.
	CourierQueueID []byte
}

// errorCodeToSentinel maps error codes to sentinel errors for StartResendingEncryptedMessage.
// This allows callers to use errors.Is() for specific error handling.
//
// The daemon sends back pigeonhole replica error codes (1-9) for replica-level errors.
// For other errors, a generic error is returned with the error code string.
func errorCodeToSentinel(errorCode uint8) error {
	switch errorCode {
	case ThinClientSuccess:
		return nil

	// Pigeonhole replica error codes (from pigeonhole/errors.go)
	case 1: // ReplicaErrorBoxIDNotFound
		return ErrBoxIDNotFound
	case 2: // ReplicaErrorInvalidBoxID
		return ErrInvalidBoxID
	case 3: // ReplicaErrorInvalidSignature
		return ErrInvalidSignature
	case 4: // ReplicaErrorDatabaseFailure
		return ErrDatabaseFailure
	case 5: // ReplicaErrorInvalidPayload
		return ErrInvalidPayload
	case 6: // ReplicaErrorStorageFull
		return ErrStorageFull
	case 7: // ReplicaErrorInternalError
		return ErrReplicaInternalError
	case 8: // ReplicaErrorInvalidEpoch
		return ErrInvalidEpoch
	case 9: // ReplicaErrorReplicationFailed
		return ErrReplicationFailed
	case 10: // ReplicaErrorBoxAlreadyExists
		return ErrBoxAlreadyExists
	case 11: // ReplicaErrorTombstone
		return ErrTombstone

	// Thin client decryption error codes
	case ThinClientErrorMKEMDecryptionFailed:
		return ErrMKEMDecryptionFailed
	case ThinClientErrorBACAPDecryptionFailed:
		return ErrBACAPDecryptionFailed

	// Thin client operation error codes
	case ThinClientErrorStartResendingCancelled:
		return ErrStartResendingCancelled
	case ThinClientErrorInvalidTombstoneSig:
		return ErrInvalidTombstoneSignature

	default:
		// For other error codes (thin client errors, etc.), return a generic error
		return errors.New(ThinClientErrorToString(errorCode))
	}
}

// NewKeypair creates a new keypair for use with the Pigeonhole protocol.
//
// This method generates a WriteCap and ReadCap from the provided seed using
// the BACAP (Blinding-and-Capability) protocol. The WriteCap should be stored
// securely for writing messages, while the ReadCap can be shared with others
// to allow them to read messages.
//
// Parameters:
//   - seed: 32-byte seed used to derive the keypair
//
// Returns:
//   - *bacap.WriteCap: Write capability for sending messages
//   - *bacap.ReadCap: Read capability that can be shared with recipients
//   - *bacap.MessageBoxIndex: First message index to use when writing
//   - error: Any error encountered during keypair creation
//
// Example:
//
//	seed := make([]byte, 32)
//	_, err := rand.Reader.Read(seed)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	writeCap, readCap, firstIndex, err := client.NewKeypair(seed)
//	if err != nil {
//		log.Fatal("Failed to create keypair:", err)
//	}
//
//	// Share readCap with Bob so he can read messages
//	// Store writeCap for sending messages
func (t *ThinClient) NewKeypair(seed []byte) (writeCap *bacap.WriteCap, readCap *bacap.ReadCap, firstMessageIndex *bacap.MessageBoxIndex, err error) {
	if len(seed) != 32 {
		return nil, nil, nil, errors.New("seed must be exactly 32 bytes")
	}

	queryID := t.NewQueryID()
	req := &Request{
		NewKeypair: &NewKeypair{
			QueryID: queryID,
			Seed:    seed,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err = t.writeMessage(req)
	if err != nil {
		return nil, nil, nil, err
	}

	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, nil, nil, errHalting
		}

		switch v := event.(type) {
		case *NewKeypairReply:
			if v.QueryID == nil {
				t.log.Debugf("NewKeypair: Received NewKeypairReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("NewKeypair: Received NewKeypairReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, nil, nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.WriteCap, v.ReadCap, v.FirstMessageIndex, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// EncryptRead encrypts a read operation for a given read capability.
//
// This method prepares an encrypted read request that can be sent to the
// courier service to retrieve a message from a pigeonhole box. The returned
// ciphertext should be sent via StartResendingEncryptedMessage.
//
// Parameters:
//   - readCap: Read capability that grants access to the channel
//   - messageBoxIndex: Starting read position for the channel
//
// Returns:
//   - []byte: Encrypted message ciphertext to send to courier
//   - []byte: Envelope descriptor for decrypting the reply
//   - *[32]byte: Hash of the courier envelope
//   - *bacap.MessageBoxIndex: Next message box index for subsequent reads
//   - error: Any error encountered during encryption
//
// Example:
//
//	ciphertext, envDesc, envHash, nextIndex, err := client.EncryptRead(
//		readCap, messageBoxIndex)
//	if err != nil {
//		log.Fatal("Failed to encrypt read:", err)
//	}
//
//	// Send ciphertext via StartResendingEncryptedMessage
func (t *ThinClient) EncryptRead(readCap *bacap.ReadCap, messageBoxIndex *bacap.MessageBoxIndex) (messageCiphertext []byte, envelopeDescriptor []byte, envelopeHash *[32]byte, nextMessageBoxIndex *bacap.MessageBoxIndex, err error) {
	if readCap == nil {
		return nil, nil, nil, nil, errors.New("readCap cannot be nil")
	}
	if messageBoxIndex == nil {
		return nil, nil, nil, nil, errors.New("messageBoxIndex cannot be nil")
	}

	queryID := t.NewQueryID()
	req := &Request{
		EncryptRead: &EncryptRead{
			QueryID:         queryID,
			ReadCap:         readCap,
			MessageBoxIndex: messageBoxIndex,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err = t.writeMessage(req)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, nil, nil, nil, errHalting
		}

		switch v := event.(type) {
		case *EncryptReadReply:
			if v.QueryID == nil {
				t.log.Debugf("EncryptRead: Received EncryptReadReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("EncryptRead: Received EncryptReadReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, nil, nil, nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.MessageCiphertext, v.EnvelopeDescriptor, v.EnvelopeHash, v.NextMessageBoxIndex, nil
		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// EncryptWrite encrypts a write operation for a given write capability.
//
// This method prepares an encrypted write request that can be sent to the
// courier service to store a message in a pigeonhole box. The returned
// ciphertext should be sent via StartResendingEncryptedMessage.
//
// Parameters:
//   - plaintext: The plaintext message to encrypt
//   - writeCap: Write capability that grants access to the channel
//   - messageBoxIndex: Starting write position for the channel
//
// Returns:
//   - []byte: Encrypted message ciphertext to send to courier
//   - []byte: Envelope descriptor for decrypting the reply
//   - *[32]byte: Hash of the courier envelope
//   - *bacap.MessageBoxIndex: Next message box index for subsequent writes
//   - error: Any error encountered during encryption
//
// Example:
//
//	plaintext := []byte("Hello, Bob!")
//	ciphertext, envDesc, envHash, nextIndex, err := client.EncryptWrite(
//		plaintext, writeCap, messageBoxIndex)
//	if err != nil {
//		log.Fatal("Failed to encrypt write:", err)
//	}
//
//	// Send ciphertext via StartResendingEncryptedMessage
func (t *ThinClient) EncryptWrite(plaintext []byte, writeCap *bacap.WriteCap, messageBoxIndex *bacap.MessageBoxIndex) (messageCiphertext []byte, envelopeDescriptor []byte, envelopeHash *[32]byte, nextMessageBoxIndex *bacap.MessageBoxIndex, err error) {
	if writeCap == nil {
		return nil, nil, nil, nil, errors.New("writeCap cannot be nil")
	}
	if messageBoxIndex == nil {
		return nil, nil, nil, nil, errors.New("messageBoxIndex cannot be nil")
	}

	queryID := t.NewQueryID()
	req := &Request{
		EncryptWrite: &EncryptWrite{
			QueryID:         queryID,
			Plaintext:       plaintext,
			WriteCap:        writeCap,
			MessageBoxIndex: messageBoxIndex,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err = t.writeMessage(req)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, nil, nil, nil, errHalting
		}

		switch v := event.(type) {
		case *EncryptWriteReply:
			if v.QueryID == nil {
				t.log.Debugf("EncryptWrite: Received EncryptWriteReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("EncryptWrite: Received EncryptWriteReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, nil, nil, nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.MessageCiphertext, v.EnvelopeDescriptor, v.EnvelopeHash, v.NextMessageBoxIndex, nil
		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// StartResendingEncryptedMessage sends an encrypted message via ARQ and blocks until completion.
//
// This method BLOCKS until a reply is received. CancelResendingEncryptedMessage is only
// useful when called from another goroutine to interrupt this blocking call.
//
// The message will be resent periodically until either:
//   - A reply is received from the courier (this method returns)
//   - The message is cancelled via CancelResendingEncryptedMessage (from another goroutine)
//   - The client is shut down
//
// This is used for both read and write operations in the new Pigeonhole API.
//
// The daemon implements a finite state machine (FSM) for handling the stop-and-wait ARQ protocol:
//   - For default write operations (writeCap != nil, readCap == nil,
//     noIdempotentBoxAlreadyExists == false):
//     The method waits for an ACK from the courier and returns immediately.
//     The ACK confirms the courier received the envelope and will dispatch it
//     to both shard replicas. This requires only a single round-trip through
//     the mixnet.
//   - For BoxAlreadyExists-aware writes (noIdempotentBoxAlreadyExists == true):
//     The method waits for an ACK, then sends a second SURB to retrieve the
//     replica's error code. This requires two round-trips through the mixnet.
//   - For read operations (readCap != nil, writeCap == nil):
//     The method waits for an ACK from the courier, then the daemon automatically
//     sends a new SURB to request the payload, and this method waits for the payload.
//     The daemon performs all decryption (MKEM envelope + BACAP payload) and returns
//     the fully decrypted plaintext.
//
// Parameters:
//   - readCap: Read capability (can be nil for write operations, required for reads)
//   - writeCap: Write capability (can be nil for read operations, required for writes)
//   - messageBoxIndex: Current message box index being operated on (required for reads)
//   - replyIndex: Index of the reply to use (typically 0 or 1)
//   - envelopeDescriptor: Serialized envelope descriptor for MKEM decryption
//   - messageCiphertext: MKEM-encrypted message to send (from EncryptRead or EncryptWrite)
//   - envelopeHash: Hash of the courier envelope
//
// Returns:
//   - *StartResendingResult: Contains Plaintext (decrypted message for reads, empty for writes),
//     CourierIdentityHash (hash of the courier that handled this message), and
//     CourierQueueID (queue ID of that courier).
//   - error: Any error encountered during the operation. Specific errors can be checked
//     using errors.Is():
//   - ErrBoxIDNotFound: The requested box ID was not found on the replica
//   - ErrInvalidBoxID: The box ID format is invalid
//   - ErrInvalidSignature: Signature verification failed
//   - ErrDatabaseFailure: Replica database error
//   - ErrInvalidPayload: Invalid payload data
//   - ErrStorageFull: Replica storage capacity exceeded
//   - ErrReplicaInternalError: Internal replica error
//   - ErrInvalidEpoch: Invalid or expired epoch
//   - ErrReplicationFailed: Replication to other replicas failed
//   - ErrMKEMDecryptionFailed: MKEM envelope decryption failed (outer layer)
//   - ErrBACAPDecryptionFailed: BACAP payload decryption failed (inner layer)
//   - ErrStartResendingCancelled: Operation was cancelled via CancelResendingEncryptedMessage
//
// Example:
//
//	result, err := client.StartResendingEncryptedMessage(
//		readCap, nil, nextIndex, &replyIdx, envDesc, ciphertext, envHash)
//	if err != nil {
//		if errors.Is(err, thin.ErrBoxIDNotFound) {
//			log.Println("Box not found - may be empty or expired")
//		} else {
//			log.Fatal("Failed to start resending:", err)
//		}
//	}
//	fmt.Printf("Received: %s\n", result.Plaintext)
func (t *ThinClient) StartResendingEncryptedMessage(readCap *bacap.ReadCap, writeCap *bacap.WriteCap, messageBoxIndex []byte, replyIndex *uint8, envelopeDescriptor []byte, messageCiphertext []byte, envelopeHash *[32]byte) (*StartResendingResult, error) {
	if envelopeHash == nil {
		return nil, errors.New("envelopeHash cannot be nil")
	}

	isRead := readCap != nil

	// Send request - the daemon will handle the FSM for ACK and payload
	if replyIndex != nil {
		t.log.Debugf("StartResendingEncryptedMessage: Sending request (isRead=%v, replyIndex=%d)", isRead, *replyIndex)
	} else {
		t.log.Debugf("StartResendingEncryptedMessage: Sending request (isRead=%v, replyIndex=nil)", isRead)
	}

	queryID := t.NewQueryID()
	req := &Request{
		StartResendingEncryptedMessage: &StartResendingEncryptedMessage{
			QueryID:            queryID,
			ReadCap:            readCap,
			WriteCap:           writeCap,
			MessageBoxIndex:    messageBoxIndex,
			ReplyIndex:         replyIndex,
			EnvelopeDescriptor: envelopeDescriptor,
			MessageCiphertext:  messageCiphertext,
			EnvelopeHash:       envelopeHash,
		},
	}

	// Track in-flight request for replay on reconnect to new daemon instance
	t.inFlightResends.Store(*envelopeHash, req)
	defer t.inFlightResends.Delete(*envelopeHash)

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	if err := t.writeMessage(req); err != nil {
		return nil, err
	}

	// Wait for reply from daemon — blocks forever until success, error, or Close()
	// For writes: daemon sends reply after receiving ACK
	// For reads: daemon sends reply after receiving payload (after ACK)
	// The daemon may also send error responses (e.g., BoxIDNotFound) which will cause this to exit
	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}

		switch v := event.(type) {
		case *StartResendingEncryptedMessageReply:
			if v.QueryID == nil {
				t.log.Debugf("StartResendingEncryptedMessage: Received reply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("StartResendingEncryptedMessage: Received reply with mismatched QueryID, ignoring")
				continue
			}

			// Check for any error (including BoxIDNotFound, internal errors, etc.)
			// Map error codes to sentinel errors for better error handling
			if v.ErrorCode != ThinClientSuccess {
				err := errorCodeToSentinel(v.ErrorCode)
				t.log.Debugf("StartResendingEncryptedMessage: Received error response: %v", err)
				return nil, err
			}

			// Success case
			// For write operations, this is the ACK reply
			// For read operations, this is the payload reply
			if !isRead {
				t.log.Debugf("StartResendingEncryptedMessage: Write operation complete")
			} else {
				t.log.Debugf("StartResendingEncryptedMessage: Read operation complete, payload length=%d", len(v.Plaintext))
			}
			return &StartResendingResult{
				Plaintext:           v.Plaintext,
				CourierIdentityHash: v.CourierIdentityHash,
				CourierQueueID:      v.CourierQueueID,
			}, nil

		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// StartResendingEncryptedMessageNoRetry is like StartResendingEncryptedMessage but disables
// automatic retries on BoxIDNotFound errors. Use this when you want immediate error feedback
// rather than waiting for potential replication lag to resolve.
// The CancelResendingEncryptedMessage method can cancel operations started with either method.
func (t *ThinClient) StartResendingEncryptedMessageNoRetry(readCap *bacap.ReadCap, writeCap *bacap.WriteCap, messageBoxIndex []byte, replyIndex *uint8, envelopeDescriptor []byte, messageCiphertext []byte, envelopeHash *[32]byte) (*StartResendingResult, error) {
	if envelopeHash == nil {
		return nil, errors.New("envelopeHash cannot be nil")
	}

	isRead := readCap != nil

	// Send request - the daemon will handle the FSM for ACK and payload
	if replyIndex != nil {
		t.log.Debugf("StartResendingEncryptedMessageNoRetry: Sending request (isRead=%v, replyIndex=%d)", isRead, *replyIndex)
	} else {
		t.log.Debugf("StartResendingEncryptedMessageNoRetry: Sending request (isRead=%v, replyIndex=nil)", isRead)
	}

	queryID := t.NewQueryID()
	req := &Request{
		StartResendingEncryptedMessage: &StartResendingEncryptedMessage{
			QueryID:                queryID,
			ReadCap:                readCap,
			WriteCap:               writeCap,
			MessageBoxIndex:        messageBoxIndex,
			ReplyIndex:             replyIndex,
			EnvelopeDescriptor:     envelopeDescriptor,
			MessageCiphertext:      messageCiphertext,
			EnvelopeHash:           envelopeHash,
			NoRetryOnBoxIDNotFound: true,
		},
	}

	// Track in-flight request for replay on reconnect to new daemon instance
	t.inFlightResends.Store(*envelopeHash, req)
	defer t.inFlightResends.Delete(*envelopeHash)

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	if err := t.writeMessage(req); err != nil {
		return nil, err
	}

	// Wait for reply from daemon
	// For writes: daemon sends reply after receiving ACK
	// For reads: daemon sends reply after receiving payload (after ACK)
	// The daemon may also send error responses (e.g., BoxIDNotFound) which will cause this to exit
	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}

		switch v := event.(type) {
		case *StartResendingEncryptedMessageReply:
			if v.QueryID == nil {
				t.log.Debugf("StartResendingEncryptedMessageNoRetry: Received reply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("StartResendingEncryptedMessageNoRetry: Received reply with mismatched QueryID, ignoring")
				continue
			}

			// Check for any error (including BoxIDNotFound, internal errors, etc.)
			// Map error codes to sentinel errors for better error handling
			if v.ErrorCode != ThinClientSuccess {
				err := errorCodeToSentinel(v.ErrorCode)
				t.log.Debugf("StartResendingEncryptedMessageNoRetry: Received error response: %v", err)
				return nil, err
			}

			// Success case
			// For write operations, this is the ACK reply
			// For read operations, this is the payload reply
			if !isRead {
				t.log.Debugf("StartResendingEncryptedMessageNoRetry: Write operation complete")
			} else {
				t.log.Debugf("StartResendingEncryptedMessageNoRetry: Read operation complete, payload length=%d", len(v.Plaintext))
			}
			return &StartResendingResult{
				Plaintext:           v.Plaintext,
				CourierIdentityHash: v.CourierIdentityHash,
				CourierQueueID:      v.CourierQueueID,
			}, nil

		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// StartResendingEncryptedMessageReturnBoxExists is like StartResendingEncryptedMessage but returns
// BoxAlreadyExists errors instead of treating them as idempotent success. Use this when you want
// to detect whether a write was actually performed or if the box already existed.
// The CancelResendingEncryptedMessage method can cancel operations started with this method.
func (t *ThinClient) StartResendingEncryptedMessageReturnBoxExists(readCap *bacap.ReadCap, writeCap *bacap.WriteCap, messageBoxIndex []byte, replyIndex *uint8, envelopeDescriptor []byte, messageCiphertext []byte, envelopeHash *[32]byte) (*StartResendingResult, error) {
	if envelopeHash == nil {
		return nil, errors.New("envelopeHash cannot be nil")
	}

	isRead := readCap != nil

	// Send request - the daemon will handle the FSM for ACK and payload
	if replyIndex != nil {
		t.log.Debugf("StartResendingEncryptedMessageReturnBoxExists: Sending request (isRead=%v, replyIndex=%d)", isRead, *replyIndex)
	} else {
		t.log.Debugf("StartResendingEncryptedMessageReturnBoxExists: Sending request (isRead=%v, replyIndex=nil)", isRead)
	}

	queryID := t.NewQueryID()
	req := &Request{
		StartResendingEncryptedMessage: &StartResendingEncryptedMessage{
			QueryID:                      queryID,
			ReadCap:                      readCap,
			WriteCap:                     writeCap,
			MessageBoxIndex:              messageBoxIndex,
			ReplyIndex:                   replyIndex,
			EnvelopeDescriptor:           envelopeDescriptor,
			MessageCiphertext:            messageCiphertext,
			EnvelopeHash:                 envelopeHash,
			NoIdempotentBoxAlreadyExists: true,
		},
	}

	// Track in-flight request for replay on reconnect to new daemon instance
	t.inFlightResends.Store(*envelopeHash, req)
	defer t.inFlightResends.Delete(*envelopeHash)

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	if err := t.writeMessage(req); err != nil {
		return nil, err
	}

	// Wait for reply from daemon
	// For writes: daemon sends reply after receiving payload (containing success or error)
	// For reads: daemon sends reply after receiving payload (after ACK)
	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}

		switch v := event.(type) {
		case *StartResendingEncryptedMessageReply:
			if v.QueryID == nil {
				t.log.Debugf("StartResendingEncryptedMessageReturnBoxExists: Received reply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("StartResendingEncryptedMessageReturnBoxExists: Received reply with mismatched QueryID, ignoring")
				continue
			}

			// Check for any error (including BoxAlreadyExists, BoxIDNotFound, internal errors, etc.)
			// Map error codes to sentinel errors for better error handling
			if v.ErrorCode != ThinClientSuccess {
				err := errorCodeToSentinel(v.ErrorCode)
				t.log.Debugf("StartResendingEncryptedMessageReturnBoxExists: Received error response: %v", err)
				return nil, err
			}

			// Success case
			// For write operations, this is the payload reply
			// For read operations, this is the payload reply
			if !isRead {
				t.log.Debugf("StartResendingEncryptedMessageReturnBoxExists: Write operation complete")
			} else {
				t.log.Debugf("StartResendingEncryptedMessageReturnBoxExists: Read operation complete, payload length=%d", len(v.Plaintext))
			}
			return &StartResendingResult{
				Plaintext:           v.Plaintext,
				CourierIdentityHash: v.CourierIdentityHash,
				CourierQueueID:      v.CourierQueueID,
			}, nil

		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// CancelResendingEncryptedMessage cancels ARQ resending for an encrypted message.
//
// This method stops the automatic repeat request (ARQ) for a previously started
// encrypted message transmission. This is useful when:
//   - A reply has been received through another channel
//   - The operation should be aborted
//   - The message is no longer needed
//
// Parameters:
//   - envelopeHash: Hash of the courier envelope to cancel
//
// Returns:
//   - error: Any error encountered during cancellation
//
// Example:
//
//	err := client.CancelResendingEncryptedMessage(envHash)
//	if err != nil {
//		log.Printf("Failed to cancel resending: %v", err)
//	}
func (t *ThinClient) CancelResendingEncryptedMessage(envelopeHash *[32]byte) error {
	if envelopeHash == nil {
		return errors.New("envelopeHash cannot be nil")
	}

	// Remove from in-flight tracking so it won't be replayed on reconnect
	t.inFlightResends.Delete(*envelopeHash)

	queryID := t.NewQueryID()
	req := &Request{
		CancelResendingEncryptedMessage: &CancelResendingEncryptedMessage{
			QueryID:      queryID,
			EnvelopeHash: envelopeHash,
		},
	}

	// If disconnected, just remove from tracking — daemon has no state to cancel
	if !t.IsConnected() {
		return nil
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return err
	}

	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return errHalting
		}

		switch v := event.(type) {
		case *CancelResendingEncryptedMessageReply:
			if v.QueryID == nil {
				t.log.Debugf("CancelResendingEncryptedMessage: Received reply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("CancelResendingEncryptedMessage: Received reply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return nil
		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// StartResendingCopyCommand sends a copy command via ARQ and blocks until completion.
//
// This method BLOCKS until a reply is received. It uses the ARQ (Automatic Repeat reQuest)
// mechanism to reliably send copy commands to the courier, automatically retrying if
// the reply is not received in time.
//
// The copy command instructs the courier to read from a temporary copy stream channel
// and write the parsed envelopes to their destination channels. The courier:
//  1. Derives a ReadCap from the WriteCap
//  2. Reads boxes from the temporary channel
//  3. Parses boxes into CourierEnvelopes
//  4. Sends each envelope to intermediate replicas for replication
//  5. Writes tombstones to clean up the temporary channel
//
// Parameters:
//   - writeCap: Write capability for the temporary copy stream channel
//
// Returns:
//   - error: Any error encountered during the operation
//
// Example:
//
//	err := client.StartResendingCopyCommand(tempWriteCap)
//	if err != nil {
//		log.Fatal("Copy command failed:", err)
//	}
func (t *ThinClient) StartResendingCopyCommand(writeCap *bacap.WriteCap) error {
	if writeCap == nil {
		return errors.New("writeCap cannot be nil")
	}

	// Compute WriteCapHash for in-flight tracking (matches daemon-side hash)
	writeCapBytes, err := writeCap.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal WriteCap: %w", err)
	}
	writeCapHash := hash.Sum256(writeCapBytes)

	queryID := t.NewQueryID()
	req := &Request{
		StartResendingCopyCommand: &StartResendingCopyCommand{
			QueryID:  queryID,
			WriteCap: writeCap,
		},
	}

	// Track in-flight request for replay on reconnect to new daemon instance
	t.inFlightResends.Store(writeCapHash, req)
	defer t.inFlightResends.Delete(writeCapHash)

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err = t.writeMessage(req)
	if err != nil {
		return err
	}

	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return errHalting
		}

		switch v := event.(type) {
		case *StartResendingCopyCommandReply:
			if v.QueryID == nil {
				t.log.Debugf("StartResendingCopyCommand: Received reply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("StartResendingCopyCommand: Received reply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return errorCodeToSentinel(v.ErrorCode)
			}
			t.log.Debugf("StartResendingCopyCommand: Copy command completed successfully")
			return nil
		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// StartResendingCopyCommandWithCourier sends a copy command to a specific courier.
//
// This method is like StartResendingCopyCommand but allows specifying which courier
// should process the copy command. This is useful for nested copy commands where
// different couriers should handle different layers for improved privacy.
//
// Parameters:
//   - writeCap: Write capability for the temporary copy stream channel
//   - courierIdentityHash: Hash of the courier's identity key
//   - courierQueueID: Queue ID for the courier service
//
// Returns:
//   - error: Any error encountered during the operation
func (t *ThinClient) StartResendingCopyCommandWithCourier(
	writeCap *bacap.WriteCap,
	courierIdentityHash *[32]byte,
	courierQueueID []byte,
) error {
	if writeCap == nil {
		return errors.New("writeCap cannot be nil")
	}
	if courierIdentityHash == nil {
		return errors.New("courierIdentityHash cannot be nil")
	}
	if len(courierQueueID) == 0 {
		return errors.New("courierQueueID cannot be empty")
	}

	// Compute WriteCapHash for in-flight tracking (matches daemon-side hash)
	writeCapBytes, err := writeCap.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal WriteCap: %w", err)
	}
	writeCapHash := hash.Sum256(writeCapBytes)

	queryID := t.NewQueryID()
	req := &Request{
		StartResendingCopyCommand: &StartResendingCopyCommand{
			QueryID:             queryID,
			WriteCap:            writeCap,
			CourierIdentityHash: courierIdentityHash,
			CourierQueueID:      courierQueueID,
		},
	}

	// Track in-flight request for replay on reconnect to new daemon instance
	t.inFlightResends.Store(writeCapHash, req)
	defer t.inFlightResends.Delete(writeCapHash)

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err = t.writeMessage(req)
	if err != nil {
		return err
	}

	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return errHalting
		}

		switch v := event.(type) {
		case *StartResendingCopyCommandReply:
			if v.QueryID == nil {
				t.log.Debugf("StartResendingCopyCommandWithCourier: Received reply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("StartResendingCopyCommandWithCourier: Received reply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return errorCodeToSentinel(v.ErrorCode)
			}
			t.log.Debugf("StartResendingCopyCommandWithCourier: Copy command completed successfully")
			return nil
		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// CancelResendingCopyCommand cancels ARQ resending for a copy command.
//
// This method stops the automatic repeat request (ARQ) for a previously started
// copy command. This is useful when:
//   - A reply has been received through another channel
//   - The operation should be aborted
//   - The copy command is no longer needed
//
// Parameters:
//   - writeCapHash: Hash of the serialized WriteCap to cancel
//
// Returns:
//   - error: Any error encountered during cancellation
//
// Example:
//
//	err := client.CancelResendingCopyCommand(writeCapHash)
//	if err != nil {
//		log.Printf("Failed to cancel copy command: %v", err)
//	}
func (t *ThinClient) CancelResendingCopyCommand(writeCapHash *[32]byte) error {
	if writeCapHash == nil {
		return errors.New("writeCapHash cannot be nil")
	}

	// Remove from in-flight tracking so it won't be replayed on reconnect
	t.inFlightResends.Delete(*writeCapHash)

	queryID := t.NewQueryID()
	req := &Request{
		CancelResendingCopyCommand: &CancelResendingCopyCommand{
			QueryID:      queryID,
			WriteCapHash: writeCapHash,
		},
	}

	// If disconnected, just remove from tracking — daemon has no state to cancel
	if !t.IsConnected() {
		return nil
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return err
	}

	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return errHalting
		}

		switch v := event.(type) {
		case *CancelResendingCopyCommandReply:
			if v.QueryID == nil {
				t.log.Debugf("CancelResendingCopyCommand: Received reply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("CancelResendingCopyCommand: Received reply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return nil
		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// NextMessageBoxIndex increments a MessageBoxIndex using the BACAP NextIndex method.
//
// This method is used when sending multiple messages to different mailboxes using
// the same WriteCap or ReadCap. It properly advances the cryptographic state by:
//   - Incrementing the Idx64 counter
//   - Deriving new encryption and blinding keys using HKDF
//   - Updating the HKDF state for the next iteration
//
// The client daemon handles the cryptographic operations using our BACAP library
// documented here: https://pkg.go.dev/github.com/katzenpost/hpqc/bacap
//
// Parameters:
//   - messageBoxIndex: Current message box index to increment
//
// Returns:
//   - *bacap.MessageBoxIndex: The next message box index
//   - error: Any error encountered during increment
//
// Example:
//
//	nextIndex, err := client.NextMessageBoxIndex(currentIndex)
//	if err != nil {
//		log.Fatal("Failed to increment index:", err)
//	}
//	// Use nextIndex for the next message
func (t *ThinClient) NextMessageBoxIndex(messageBoxIndex *bacap.MessageBoxIndex) (nextMessageBoxIndex *bacap.MessageBoxIndex, err error) {
	if messageBoxIndex == nil {
		return nil, errors.New("messageBoxIndex cannot be nil")
	}

	queryID := t.NewQueryID()
	req := &Request{
		NextMessageBoxIndex: &NextMessageBoxIndex{
			QueryID:         queryID,
			MessageBoxIndex: messageBoxIndex,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err = t.writeMessage(req)
	if err != nil {
		return nil, err
	}

	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}

		switch v := event.(type) {
		case *NextMessageBoxIndexReply:
			if v.QueryID == nil {
				t.log.Debugf("NextMessageBoxIndex: Received reply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("NextMessageBoxIndex: Received reply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.NextMessageBoxIndex, nil
		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// CreateEnvelopesResult contains the result of creating courier envelopes,
// including the envelopes, buffer state for crash recovery, and next destination indices.
type CreateEnvelopesResult struct {
	// Envelopes contains the serialized CopyStreamElements ready to be written to boxes.
	Envelopes [][]byte

	// Buffer contains any data buffered by the encoder that hasn't been output yet.
	// This can be persisted for crash recovery and restored via SetStreamBuffer.
	Buffer []byte

	// NextDestIndices contains the next destination message box index for each
	// destination, in the same order as the destinations in the request.
	NextDestIndices []*bacap.MessageBoxIndex
}

// NewStreamID generates a new cryptographically random stream identifier.
// Stream IDs are used to correlate multiple CreateCourierEnvelopesFromPayload
// and CreateCourierEnvelopesFromMultiPayload calls that belong to the same
// copy stream. Each stream should have a unique ID.
//
// Returns:
//   - *[StreamIDLength]byte: A new random stream ID
//
// Panics:
//   - If the random number generator fails
func (t *ThinClient) NewStreamID() *[StreamIDLength]byte {
	id := new([StreamIDLength]byte)
	_, err := rand.Reader.Read(id[:])
	if err != nil {
		panic(err)
	}
	return id
}

// SetStreamBuffer restores the buffered encoder state for a given stream ID.
// This is useful for crash recovery: after a restart, call this with the buffer
// that was returned in CreateEnvelopesResult.Buffer before the crash, then
// continue calling CreateCourierEnvelopesFromMultiPayload as normal.
func (t *ThinClient) SetStreamBuffer(streamID *[StreamIDLength]byte, buffer []byte) error {
	if streamID == nil {
		return errors.New("streamID cannot be nil")
	}

	queryID := t.NewQueryID()
	req := &Request{
		SetStreamBuffer: &SetStreamBuffer{
			QueryID:  queryID,
			StreamID: streamID,
			Buffer:   buffer,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return err
	}

	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return errHalting
		}

		switch v := event.(type) {
		case *SetStreamBufferReply:
			if v.QueryID == nil {
				t.log.Debugf("SetStreamBuffer: Received reply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("SetStreamBuffer: Received reply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return nil
		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// CreateCourierEnvelopesFromPayload creates multiple CourierEnvelopes from a payload of any size.
//
// This method is stateless — no daemon state is kept between calls. Each call creates
// a fresh encoder, encodes all envelopes, flushes, and returns. The payload is limited
// to 10MB to prevent accidental memory exhaustion.
//
// Each returned chunk is a serialized CopyStreamElement ready to be written to a box.
// The caller controls the copy stream boundaries via isStart and isLast flags.
//
// The returned chunks must be written to a temporary copy stream channel using
// EncryptWrite + StartResendingEncryptedMessage. After the stream is complete,
// send a Copy command to the courier with the write capability for the temp stream.
//
// Parameters:
//   - payload: The data to be written (max 10MB)
//   - destWriteCap: Write capability for the destination channel
//   - destStartIndex: Starting index in the destination channel
//   - isStart: Whether this is the first call (sets IsStart flag on first element)
//   - isLast: Whether this is the last call (sets IsFinal flag on last element)
//
// Returns:
//   - [][]byte: Slice of CopyStreamElements ready to write to the copy stream
//   - *bacap.MessageBoxIndex: Next destination index (use as destStartIndex in next call)
//   - error: Any error encountered during envelope creation
func (t *ThinClient) CreateCourierEnvelopesFromPayload(payload []byte, destWriteCap *bacap.WriteCap, destStartIndex *bacap.MessageBoxIndex, isStart bool, isLast bool) (envelopes [][]byte, nextDestIndex *bacap.MessageBoxIndex, err error) {
	if destWriteCap == nil {
		return nil, nil, errors.New("destWriteCap cannot be nil")
	}
	if destStartIndex == nil {
		return nil, nil, errors.New("destStartIndex cannot be nil")
	}

	queryID := t.NewQueryID()
	req := &Request{
		CreateCourierEnvelopesFromPayload: &CreateCourierEnvelopesFromPayload{
			QueryID:        queryID,
			Payload:        payload,
			DestWriteCap:   destWriteCap,
			DestStartIndex: destStartIndex,
			IsStart:        isStart,
			IsLast:         isLast,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err = t.writeMessage(req)
	if err != nil {
		return nil, nil, err
	}

	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, nil, errHalting
		}

		switch v := event.(type) {
		case *CreateCourierEnvelopesFromPayloadReply:
			if v.QueryID == nil {
				t.log.Debugf("CreateCourierEnvelopesFromPayload: Received reply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("CreateCourierEnvelopesFromPayload: Received reply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.Envelopes, v.NextDestIndex, nil
		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// CreateCourierEnvelopesFromMultiPayload creates CourierEnvelopes from multiple payloads
// going to different destination channels. This is more space-efficient than calling
// CreateCourierEnvelopesFromPayload multiple times because all envelopes from all
// destinations are packed together in the same encoder without wasting space.
//
// This method causes the client daemon to save state between multiple calls using the
// same streamID. The streamID should be unique for each copy stream. Each reply includes
// the current buffer state that can be persisted for crash recovery via SetStreamBuffer.
//
// Parameters:
//   - streamID: Unique identifier for the stream (use NewStreamID() for first call)
//   - destinations: Slice of DestinationPayload specifying payloads and their destination channels
//   - isLast: Set to true on the final call to flush the encoder
//
// Returns:
//   - *CreateEnvelopesResult: Contains envelopes, buffer state, and NextDestIndices
//   - error: Any error encountered
func (t *ThinClient) CreateCourierEnvelopesFromMultiPayload(streamID *[StreamIDLength]byte, destinations []DestinationPayload, isLast bool) (*CreateEnvelopesResult, error) {
	if streamID == nil {
		return nil, errors.New("streamID cannot be nil")
	}
	if len(destinations) == 0 {
		return nil, errors.New("destinations cannot be empty")
	}

	queryID := t.NewQueryID()
	req := &Request{
		CreateCourierEnvelopesFromPayloads: &CreateCourierEnvelopesFromPayloads{
			QueryID:      queryID,
			StreamID:     streamID,
			Destinations: destinations,
			IsLast:       isLast,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return nil, err
	}

	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}

		switch v := event.(type) {
		case *CreateCourierEnvelopesFromPayloadsReply:
			if v.QueryID == nil {
				t.log.Debugf("CreateCourierEnvelopesFromMultiPayload: Received reply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("CreateCourierEnvelopesFromMultiPayload: Received reply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return &CreateEnvelopesResult{
				Envelopes:       v.Envelopes,
				Buffer:          v.Buffer,
				NextDestIndices: v.NextDestIndices,
			}, nil
		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// Copy Channel API:

// SendCopyCommand sends a Copy command to the courier service.
//
// The Copy command instructs the client daemon to send a Copy command to the
// courier. This Copy command sent to the courier instructs it to read encrypted
// write operations from a temporary copy stream (identified by tempWriteCap)
// and execute them atomically. This provides all-or-nothing retransmission
// to prevent correlation attacks.
//
// The workflow is:
// 1. Create temporary copy stream channel using NewKeypair
// 2. Call CreateCourierEnvelopesFromPayload many times until finished.
// 3. Write envelopes to copy stream using EncryptWrite + StartResendingEncryptedMessage
// 4. Send Copy command with WriteCap using StartResendingCopyCommand

// CourierDescriptor identifies a specific courier service for routing copy commands.
type CourierDescriptor struct {
	IdentityHash *[32]byte
	QueueID      []byte
}

// GetAllCouriers returns all available courier services from the current PKI document.
// Use this to select specific couriers for nested copy commands.
func (t *ThinClient) GetAllCouriers() (couriers []CourierDescriptor, err error) {
	services, err := t.GetServices("courier")
	if err != nil {
		return nil, err
	}
	couriers = make([]CourierDescriptor, len(services))
	for i, svc := range services {
		idHash := hashIdentityKey(svc.MixDescriptor.IdentityKey)
		couriers[i] = CourierDescriptor{
			IdentityHash: &idHash,
			QueueID:      svc.RecipientQueueID,
		}
	}
	return couriers, nil
}

// GetDistinctCouriers returns N distinct random couriers.
// Returns an error if fewer than N couriers are available.
func (t *ThinClient) GetDistinctCouriers(n int) (couriers []CourierDescriptor, err error) {
	couriers, err = t.GetAllCouriers()
	if err != nil {
		return nil, err
	}
	if len(couriers) < n {
		return nil, errors.New("not enough couriers available")
	}
	// Shuffle and take first N
	perm := rand.NewMath().Perm(len(couriers))
	result := make([]CourierDescriptor, n)
	for i := 0; i < n; i++ {
		result[i] = couriers[perm[i]]
	}
	return result, nil
}

// hashIdentityKey computes the hash of an identity key
func hashIdentityKey(key []byte) [32]byte {
	return hash.Sum256(key)
}

type TombstoneEnvelope struct {
	MessageCiphertext  []byte
	EnvelopeDescriptor []byte
	EnvelopeHash       *[32]byte
	BoxIndex           *bacap.MessageBoxIndex
}

type TombstoneRangeResult struct {
	Envelopes []*TombstoneEnvelope
	Next      *bacap.MessageBoxIndex
}

// TombstoneRange creates tombstones for a range of pigeonhole boxes.
// Tombstones are created by calling EncryptWrite with an empty plaintext.
// The daemon detects this and signs empty payloads instead of encrypting,
// which the replica recognizes as deletion requests.
//
// To tombstone a single box, use maxCount=1.
func (c *ThinClient) TombstoneRange(
	writeCap *bacap.WriteCap,
	start *bacap.MessageBoxIndex,
	maxCount uint32,
) (result *TombstoneRangeResult, err error) {

	if writeCap == nil {
		return nil, fmt.Errorf("nil writeCap")
	}
	if start == nil {
		return nil, fmt.Errorf("nil start index")
	}
	if maxCount == 0 {
		return &TombstoneRangeResult{Envelopes: nil, Next: start}, nil
	}

	cur := start
	envelopes := make([]*TombstoneEnvelope, 0, maxCount)

	for uint32(len(envelopes)) < maxCount {
		messageCiphertext, envelopeDescriptor, envelopeHash, nextIndex, err := c.EncryptWrite([]byte{}, writeCap, cur)
		if err != nil {
			return &TombstoneRangeResult{
				Envelopes: envelopes,
				Next:      cur,
			}, err
		}

		envelopes = append(envelopes, &TombstoneEnvelope{
			MessageCiphertext:  messageCiphertext,
			EnvelopeDescriptor: envelopeDescriptor,
			EnvelopeHash:       envelopeHash,
			BoxIndex:           cur,
		})

		cur = nextIndex
	}

	return &TombstoneRangeResult{
		Envelopes: envelopes,
		Next:      cur,
	}, nil
}
