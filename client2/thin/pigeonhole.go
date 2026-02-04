// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"bytes"
	"context"
	"errors"

	"github.com/katzenpost/hpqc/bacap"
)

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

	// Thin client decryption error codes
	case ThinClientErrorMKEMDecryptionFailed:
		return ErrMKEMDecryptionFailed
	case ThinClientErrorBACAPDecryptionFailed:
		return ErrBACAPDecryptionFailed

	// Thin client operation error codes
	case ThinClientErrorStartResendingCancelled:
		return ErrStartResendingCancelled

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
//   - ctx: Context for cancellation and timeout control
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
//	ctx := context.Background()
//	seed := make([]byte, 32)
//	_, err := rand.Reader.Read(seed)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	writeCap, readCap, firstIndex, err := client.NewKeypair(ctx, seed)
//	if err != nil {
//		log.Fatal("Failed to create keypair:", err)
//	}
//
//	// Share readCap with Bob so he can read messages
//	// Store writeCap for sending messages
func (t *ThinClient) NewKeypair(ctx context.Context, seed []byte) (*bacap.WriteCap, *bacap.ReadCap, *bacap.MessageBoxIndex, error) {
	if ctx == nil {
		return nil, nil, nil, errContextCannotBeNil
	}
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

	err := t.writeMessage(req)
	if err != nil {
		return nil, nil, nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
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
//   - ctx: Context for cancellation and timeout control
//   - readCap: Read capability that grants access to the channel
//   - messageBoxIndex: Starting read position for the channel
//
// Returns:
//   - []byte: Encrypted message ciphertext to send to courier
//   - []byte: Next message index for subsequent reads
//   - []byte: Envelope descriptor for decrypting the reply
//   - *[32]byte: Hash of the courier envelope
//   - uint64: Replica epoch when envelope was created
//   - error: Any error encountered during encryption
//
// Example:
//
//	ctx := context.Background()
//	ciphertext, nextIndex, envDesc, envHash, epoch, err := client.EncryptRead(
//		ctx, readCap, messageBoxIndex)
//	if err != nil {
//		log.Fatal("Failed to encrypt read:", err)
//	}
//
//	// Send ciphertext via StartResendingEncryptedMessage
func (t *ThinClient) EncryptRead(ctx context.Context, readCap *bacap.ReadCap, messageBoxIndex *bacap.MessageBoxIndex) ([]byte, []byte, []byte, *[32]byte, uint64, error) {
	if ctx == nil {
		return nil, nil, nil, nil, 0, errContextCannotBeNil
	}
	if readCap == nil {
		return nil, nil, nil, nil, 0, errors.New("readCap cannot be nil")
	}
	if messageBoxIndex == nil {
		return nil, nil, nil, nil, 0, errors.New("messageBoxIndex cannot be nil")
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

	err := t.writeMessage(req)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, nil, nil, nil, 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, nil, nil, nil, 0, errHalting
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
				return nil, nil, nil, nil, 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.MessageCiphertext, v.NextMessageIndex, v.EnvelopeDescriptor, v.EnvelopeHash, v.ReplicaEpoch, nil
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
//   - ctx: Context for cancellation and timeout control
//   - plaintext: The plaintext message to encrypt
//   - writeCap: Write capability that grants access to the channel
//   - messageBoxIndex: Starting write position for the channel
//
// Returns:
//   - []byte: Encrypted message ciphertext to send to courier
//   - []byte: Envelope descriptor for decrypting the reply
//   - *[32]byte: Hash of the courier envelope
//   - uint64: Replica epoch when envelope was created
//   - error: Any error encountered during encryption
//
// Example:
//
//	ctx := context.Background()
//	plaintext := []byte("Hello, Bob!")
//	ciphertext, envDesc, envHash, epoch, err := client.EncryptWrite(
//		ctx, plaintext, writeCap, messageBoxIndex)
//	if err != nil {
//		log.Fatal("Failed to encrypt write:", err)
//	}
//
//	// Send ciphertext via StartResendingEncryptedMessage
func (t *ThinClient) EncryptWrite(ctx context.Context, plaintext []byte, writeCap *bacap.WriteCap, messageBoxIndex *bacap.MessageBoxIndex) ([]byte, []byte, *[32]byte, uint64, error) {
	if ctx == nil {
		return nil, nil, nil, 0, errContextCannotBeNil
	}
	if writeCap == nil {
		return nil, nil, nil, 0, errors.New("writeCap cannot be nil")
	}
	if messageBoxIndex == nil {
		return nil, nil, nil, 0, errors.New("messageBoxIndex cannot be nil")
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

	err := t.writeMessage(req)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, nil, nil, 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, nil, nil, 0, errHalting
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
				return nil, nil, nil, 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.MessageCiphertext, v.EnvelopeDescriptor, v.EnvelopeHash, v.ReplicaEpoch, nil
		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// StartResendingEncryptedMessage starts resending an encrypted message via ARQ.
//
// This method initiates automatic repeat request (ARQ) for an encrypted message,
// which will be resent periodically until either:
//   - A reply is received from the courier
//   - The message is cancelled via CancelResendingEncryptedMessage
//   - The client is shut down
//
// This is used for both read and write operations in the new Pigeonhole API.
//
// The daemon implements a finite state machine (FSM) for handling the stop-and-wait ARQ protocol:
//   - For write operations (writeCap != nil, readCap == nil):
//     The method waits for an ACK from the courier and returns immediately.
//   - For read operations (readCap != nil, writeCap == nil):
//     The method waits for an ACK from the courier, then the daemon automatically
//     sends a new SURB to request the payload, and this method waits for the payload.
//     The daemon performs all decryption (MKEM envelope + BACAP payload) and returns
//     the fully decrypted plaintext.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - readCap: Read capability (can be nil for write operations, required for reads)
//   - writeCap: Write capability (can be nil for read operations, required for writes)
//   - nextMessageIndex: Next message index for BACAP decryption (required for reads)
//   - replyIndex: Index of the reply to use (typically 0 or 1)
//   - envelopeDescriptor: Serialized envelope descriptor for MKEM decryption
//   - messageCiphertext: MKEM-encrypted message to send (from EncryptRead or EncryptWrite)
//   - envelopeHash: Hash of the courier envelope
//   - replicaEpoch: Epoch when the envelope was created
//
// Returns:
//   - []byte: Fully decrypted plaintext from the reply (for reads) or empty (for writes)
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
//	ctx := context.Background()
//	plaintext, err := client.StartResendingEncryptedMessage(
//		ctx, readCap, nil, nextIndex, &replyIdx, envDesc, ciphertext, envHash, epoch)
//	if err != nil {
//		if errors.Is(err, thin.ErrBoxIDNotFound) {
//			log.Println("Box not found - may be empty or expired")
//		} else {
//			log.Fatal("Failed to start resending:", err)
//		}
//	}
//	fmt.Printf("Received: %s\n", plaintext)
func (t *ThinClient) StartResendingEncryptedMessage(ctx context.Context, readCap *bacap.ReadCap, writeCap *bacap.WriteCap, nextMessageIndex []byte, replyIndex *uint8, envelopeDescriptor []byte, messageCiphertext []byte, envelopeHash *[32]byte, replicaEpoch uint64) ([]byte, error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}
	if envelopeHash == nil {
		return nil, errors.New("envelopeHash cannot be nil")
	}

	isRead := readCap != nil

	// Send request - the daemon will handle the FSM for ACK and payload
	t.log.Debugf("StartResendingEncryptedMessage: Sending request (isRead=%v, replyIndex=%d)", isRead, *replyIndex)

	queryID := t.NewQueryID()
	req := &Request{
		StartResendingEncryptedMessage: &StartResendingEncryptedMessage{
			QueryID:            queryID,
			ReadCap:            readCap,
			WriteCap:           writeCap,
			NextMessageIndex:   nextMessageIndex,
			ReplyIndex:         replyIndex,
			EnvelopeDescriptor: envelopeDescriptor,
			MessageCiphertext:  messageCiphertext,
			EnvelopeHash:       envelopeHash,
			ReplicaEpoch:       replicaEpoch,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return nil, err
	}

	// Wait for reply from daemon
	// For writes: daemon sends reply after receiving ACK
	// For reads: daemon sends reply after receiving payload (after ACK)
	// The daemon may also send error responses (e.g., BoxIDNotFound) which will cause this to exit
	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
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
			return v.Plaintext, nil

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
//   - ctx: Context for cancellation and timeout control
//   - envelopeHash: Hash of the courier envelope to cancel
//
// Returns:
//   - error: Any error encountered during cancellation
//
// Example:
//
//	ctx := context.Background()
//	err := client.CancelResendingEncryptedMessage(ctx, envHash)
//	if err != nil {
//		log.Printf("Failed to cancel resending: %v", err)
//	}
func (t *ThinClient) CancelResendingEncryptedMessage(ctx context.Context, envelopeHash *[32]byte) error {
	if ctx == nil {
		return errContextCannotBeNil
	}
	if envelopeHash == nil {
		return errors.New("envelopeHash cannot be nil")
	}

	queryID := t.NewQueryID()
	req := &Request{
		CancelResendingEncryptedMessage: &CancelResendingEncryptedMessage{
			QueryID:      queryID,
			EnvelopeHash: envelopeHash,
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
		case <-ctx.Done():
			return ctx.Err()
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
