// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"bytes"
	"context"
	"errors"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"
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
func (t *ThinClient) NewKeypair(ctx context.Context, seed []byte) (writeCap *bacap.WriteCap, readCap *bacap.ReadCap, firstMessageIndex *bacap.MessageBoxIndex, err error) {
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

	err = t.writeMessage(req)
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
//   - error: Any error encountered during encryption
//
// Example:
//
//	ctx := context.Background()
//	ciphertext, nextIndex, envDesc, envHash, err := client.EncryptRead(
//		ctx, readCap, messageBoxIndex)
//	if err != nil {
//		log.Fatal("Failed to encrypt read:", err)
//	}
//
//	// Send ciphertext via StartResendingEncryptedMessage
func (t *ThinClient) EncryptRead(ctx context.Context, readCap *bacap.ReadCap, messageBoxIndex *bacap.MessageBoxIndex) (messageCiphertext []byte, nextMessageIndex []byte, envelopeDescriptor []byte, envelopeHash *[32]byte, err error) {
	if ctx == nil {
		return nil, nil, nil, nil, errContextCannotBeNil
	}
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
		case <-ctx.Done():
			return nil, nil, nil, nil, ctx.Err()
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
			return v.MessageCiphertext, v.NextMessageIndex, v.EnvelopeDescriptor, v.EnvelopeHash, nil
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
//   - error: Any error encountered during encryption
//
// Example:
//
//	ctx := context.Background()
//	plaintext := []byte("Hello, Bob!")
//	ciphertext, envDesc, envHash, err := client.EncryptWrite(
//		ctx, plaintext, writeCap, messageBoxIndex)
//	if err != nil {
//		log.Fatal("Failed to encrypt write:", err)
//	}
//
//	// Send ciphertext via StartResendingEncryptedMessage
func (t *ThinClient) EncryptWrite(ctx context.Context, plaintext []byte, writeCap *bacap.WriteCap, messageBoxIndex *bacap.MessageBoxIndex) (messageCiphertext []byte, envelopeDescriptor []byte, envelopeHash *[32]byte, err error) {
	if ctx == nil {
		return nil, nil, nil, errContextCannotBeNil
	}
	if writeCap == nil {
		return nil, nil, nil, errors.New("writeCap cannot be nil")
	}
	if messageBoxIndex == nil {
		return nil, nil, nil, errors.New("messageBoxIndex cannot be nil")
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
				return nil, nil, nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.MessageCiphertext, v.EnvelopeDescriptor, v.EnvelopeHash, nil
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
//		ctx, readCap, nil, nextIndex, &replyIdx, envDesc, ciphertext, envHash)
//	if err != nil {
//		if errors.Is(err, thin.ErrBoxIDNotFound) {
//			log.Println("Box not found - may be empty or expired")
//		} else {
//			log.Fatal("Failed to start resending:", err)
//		}
//	}
//	fmt.Printf("Received: %s\n", plaintext)
func (t *ThinClient) StartResendingEncryptedMessage(ctx context.Context, readCap *bacap.ReadCap, writeCap *bacap.WriteCap, nextMessageIndex []byte, replyIndex *uint8, envelopeDescriptor []byte, messageCiphertext []byte, envelopeHash *[32]byte) (plaintext []byte, err error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}
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
			NextMessageIndex:   nextMessageIndex,
			ReplyIndex:         replyIndex,
			EnvelopeDescriptor: envelopeDescriptor,
			MessageCiphertext:  messageCiphertext,
			EnvelopeHash:       envelopeHash,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err = t.writeMessage(req)
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
//   - ctx: Context for cancellation and timeout control
//   - writeCap: Write capability for the temporary copy stream channel
//
// Returns:
//   - error: Any error encountered during the operation
//
// Example:
//
//	ctx := context.Background()
//	err := client.StartResendingCopyCommand(ctx, tempWriteCap)
//	if err != nil {
//		log.Fatal("Copy command failed:", err)
//	}
func (t *ThinClient) StartResendingCopyCommand(ctx context.Context, writeCap *bacap.WriteCap) error {
	if ctx == nil {
		return errContextCannotBeNil
	}
	if writeCap == nil {
		return errors.New("writeCap cannot be nil")
	}

	queryID := t.NewQueryID()
	req := &Request{
		StartResendingCopyCommand: &StartResendingCopyCommand{
			QueryID:  queryID,
			WriteCap: writeCap,
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
//   - ctx: Context for cancellation and timeout control
//   - writeCap: Write capability for the temporary copy stream channel
//   - courierIdentityHash: Hash of the courier's identity key
//   - courierQueueID: Queue ID for the courier service
//
// Returns:
//   - error: Any error encountered during the operation
func (t *ThinClient) StartResendingCopyCommandWithCourier(
	ctx context.Context,
	writeCap *bacap.WriteCap,
	courierIdentityHash *[32]byte,
	courierQueueID []byte,
) error {
	if ctx == nil {
		return errContextCannotBeNil
	}
	if writeCap == nil {
		return errors.New("writeCap cannot be nil")
	}
	if courierIdentityHash == nil {
		return errors.New("courierIdentityHash cannot be nil")
	}
	if len(courierQueueID) == 0 {
		return errors.New("courierQueueID cannot be empty")
	}

	queryID := t.NewQueryID()
	req := &Request{
		StartResendingCopyCommand: &StartResendingCopyCommand{
			QueryID:             queryID,
			WriteCap:            writeCap,
			CourierIdentityHash: courierIdentityHash,
			CourierQueueID:      courierQueueID,
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
//   - ctx: Context for cancellation and timeout control
//   - writeCapHash: Hash of the serialized WriteCap to cancel
//
// Returns:
//   - error: Any error encountered during cancellation
//
// Example:
//
//	ctx := context.Background()
//	err := client.CancelResendingCopyCommand(ctx, writeCapHash)
//	if err != nil {
//		log.Printf("Failed to cancel copy command: %v", err)
//	}
func (t *ThinClient) CancelResendingCopyCommand(ctx context.Context, writeCapHash *[32]byte) error {
	if ctx == nil {
		return errContextCannotBeNil
	}
	if writeCapHash == nil {
		return errors.New("writeCapHash cannot be nil")
	}

	queryID := t.NewQueryID()
	req := &Request{
		CancelResendingCopyCommand: &CancelResendingCopyCommand{
			QueryID:      queryID,
			WriteCapHash: writeCapHash,
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
//   - ctx: Context for cancellation and timeout control
//   - messageBoxIndex: Current message box index to increment
//
// Returns:
//   - *bacap.MessageBoxIndex: The next message box index
//   - error: Any error encountered during increment
//
// Example:
//
//	ctx := context.Background()
//	nextIndex, err := client.NextMessageBoxIndex(ctx, currentIndex)
//	if err != nil {
//		log.Fatal("Failed to increment index:", err)
//	}
//	// Use nextIndex for the next message
func (t *ThinClient) NextMessageBoxIndex(ctx context.Context, messageBoxIndex *bacap.MessageBoxIndex) (nextMessageBoxIndex *bacap.MessageBoxIndex, err error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}
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
		case <-ctx.Done():
			return nil, ctx.Err()
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

// NewStreamID generates a new cryptographically random stream identifier.
//
// Stream IDs are used to correlate multiple CreateCourierEnvelopesFromPayload
// and CreateCourierEnvelopesFromPayloads
// calls that belong to the same copy stream. Each stream should have a unique ID.
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

// CreateCourierEnvelopesFromPayload creates multiple CourierEnvelopes from a payload of any size.
//
// This method automatically chunks the payload into appropriately-sized pieces and
// creates a CourierEnvelope for each chunk. The payload is limited to 10MB to prevent
// accidental memory exhaustion.
//
// Each returned chunk is a serialized CopyStreamElement ready to be written to a box.
// The CopyStreamElement has a flags fields for indicating the first and last box in the stream.
//
// The returned chunks must be written to a temporary copy stream channel using
// EncryptWrite + StartResendingEncryptedMessage. After the stream is complete,
// a Copy command sent to the courier which contains the write capability for the
// temporary copy stream.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - streamID: Identifies the encoder instance (use NewStreamID() for first call)
//   - payload: The data to be written (max 10MB)
//   - destWriteCap: Write capability for the destination channel
//   - destStartIndex: Starting index in the destination channel
//   - isLast: Whether this is the last payload in the sequence (sets IsFinal flag)
//
// Returns:
//   - [][]byte: Slice of CopyStreamElements ready to write to the copy stream
//   - error: Any error encountered during envelope creation
//
// Example:
//
//	ctx := context.Background()
//	streamID := client.NewStreamID()
//	largePayload := make([]byte, 1024*1024) // 1MB payload
//	chunks, err := client.CreateCourierEnvelopesFromPayload(ctx, streamID, largePayload, destWriteCap, destStartIndex, true)
//	if err != nil {
//		log.Fatal("Failed to create envelopes:", err)
//	}
//
//	// Write each chunk to the copy stream
//	copyIndex := copyStartIndex
//	for _, chunk := range chunks {
//		ciphertext, envDesc, envHash, epoch, err := client.EncryptWrite(ctx, chunk, copyWriteCap, copyIndex)
//		if err != nil {
//			log.Fatal("Failed to encrypt chunk:", err)
//		}
//		_, err = client.StartResendingEncryptedMessage(ctx, nil, copyWriteCap, copyIndex.Bytes(), nil, envDesc, ciphertext, envHash, epoch)
//		if err != nil {
//			log.Fatal("Failed to send chunk:", err)
//		}
//		copyIndex, _ = client.NextMessageBoxIndex(ctx, copyIndex)
//	}
//
//	// Send Copy command to courier
//	errorCode, err := client.SendCopyCommand(ctx, copyReadCap, courierIdHash, courierQueueID)
//	if err != nil || errorCode != 0 {
//		log.Fatal("Copy command failed")
//	}
func (t *ThinClient) CreateCourierEnvelopesFromPayload(ctx context.Context, streamID *[StreamIDLength]byte, payload []byte, destWriteCap *bacap.WriteCap, destStartIndex *bacap.MessageBoxIndex, isLast bool) (envelopes [][]byte, err error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}
	if streamID == nil {
		return nil, errors.New("streamID cannot be nil")
	}
	if destWriteCap == nil {
		return nil, errors.New("destWriteCap cannot be nil")
	}
	if destStartIndex == nil {
		return nil, errors.New("destStartIndex cannot be nil")
	}

	queryID := t.NewQueryID()
	req := &Request{
		CreateCourierEnvelopesFromPayload: &CreateCourierEnvelopesFromPayload{
			QueryID:        queryID,
			StreamID:       streamID,
			Payload:        payload,
			DestWriteCap:   destWriteCap,
			DestStartIndex: destStartIndex,
			IsLast:         isLast,
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
		case <-ctx.Done():
			return nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
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
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.Envelopes, nil
		case *ConnectionStatusEvent:
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// CreateCourierEnvelopesFromPayloads creates CourierEnvelopes from multiple payloads
// going to different destination channels. This is more space-efficient than calling
// CreateCourierEnvelopesFromPayload multiple times because all envelopes from all
// destinations are packed together in the same encoder without wasting space.
//
// Parameters:
//   - ctx: Context for cancellation
//   - streamID: Unique identifier for the stream (use NewStreamID() for first call)
//   - destinations: Slice of DestinationPayload specifying payloads and their destination channels
//   - isLast: Set to true on the final call to flush the encoder
//
// Returns:
//   - [][]byte: Serialized CopyStreamElements ready to be written to boxes
//   - error: Any error encountered
func (t *ThinClient) CreateCourierEnvelopesFromPayloads(ctx context.Context, streamID *[StreamIDLength]byte, destinations []DestinationPayload, isLast bool) (envelopes [][]byte, err error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}
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

	err = t.writeMessage(req)
	if err != nil {
		return nil, err
	}

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
		case *CreateCourierEnvelopesFromPayloadsReply:
			if v.QueryID == nil {
				t.log.Debugf("CreateCourierEnvelopesFromPayloads: Received reply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("CreateCourierEnvelopesFromPayloads: Received reply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.Envelopes, nil
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

// SendNestedCopy sends a payload through N couriers using nested copy commands.
//
// This high-level API abstracts all the complexity of nested copy commands.
// The payload is wrapped in len(courierPath) layers and each layer is processed
// by a different courier, providing compartmentalization - no single courier
// knows the full path from source to destination.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - payload: The data to deliver to the destination
//   - destWriteCap: Write capability for the final destination channel
//   - destFirstIndex: Starting index in the destination channel
//   - courierPath: List of couriers, one per layer (first courier handles outermost layer)
//
// Returns:
//   - error: Any error encountered during the operation
func (t *ThinClient) SendNestedCopy(
	ctx context.Context,
	payload []byte,
	destWriteCap *bacap.WriteCap,
	destFirstIndex *bacap.MessageBoxIndex,
	courierPath []CourierDescriptor,
) error {
	if ctx == nil {
		return errContextCannotBeNil
	}
	if len(payload) == 0 {
		return errors.New("payload cannot be empty")
	}
	if destWriteCap == nil {
		return errors.New("destWriteCap cannot be nil")
	}
	if destFirstIndex == nil {
		return errors.New("destFirstIndex cannot be nil")
	}
	if len(courierPath) == 0 {
		return errors.New("courierPath cannot be empty")
	}

	depth := len(courierPath)

	// Create N-1 intermediate channels
	type intermediateChannel struct {
		writeCap   *bacap.WriteCap
		readCap    *bacap.ReadCap
		firstIndex *bacap.MessageBoxIndex
	}
	intermediates := make([]intermediateChannel, depth-1)
	for i := range depth - 1 {
		seed := make([]byte, 32)
		_, err := rand.Reader.Read(seed)
		if err != nil {
			return err
		}
		writeCap, readCap, firstIdx, err := t.NewKeypair(ctx, seed)
		if err != nil {
			return err
		}
		intermediates[i] = intermediateChannel{writeCap: writeCap, readCap: readCap, firstIndex: firstIdx}
	}

	// Build layers from inside-out
	type layerData struct {
		chunks [][]byte
		blob   []byte
	}
	layers := make([]layerData, depth)
	currentPayload := payload

	for layer := range depth {
		var targetWriteCap *bacap.WriteCap
		var targetFirstIndex *bacap.MessageBoxIndex
		if layer == 0 {
			targetWriteCap = destWriteCap
			targetFirstIndex = destFirstIndex
		} else {
			targetWriteCap = intermediates[layer-1].writeCap
			targetFirstIndex = intermediates[layer-1].firstIndex
		}

		streamID := t.NewStreamID()
		chunks, err := t.CreateCourierEnvelopesFromPayload(
			ctx, streamID, currentPayload, targetWriteCap, targetFirstIndex, true)
		if err != nil {
			return err
		}

		var blob []byte
		for _, chunk := range chunks {
			blob = append(blob, chunk...)
		}
		layers[layer] = layerData{chunks: chunks, blob: blob}
		currentPayload = blob
	}

	// Execute N CopyCommands (outermost to innermost)
	replyIndex := uint8(0)
	for cmdNum := range depth {
		layerIdx := depth - 1 - cmdNum
		courier := courierPath[cmdNum]

		// Create temp channel for this CopyCommand
		execTempSeed := make([]byte, 32)
		_, err := rand.Reader.Read(execTempSeed)
		if err != nil {
			return err
		}
		execTempWriteCap, _, execTempFirstIndex, err := t.NewKeypair(ctx, execTempSeed)
		if err != nil {
			return err
		}

		// Write chunks to temp channel
		chunksToWrite := layers[layerIdx].chunks
		execTempIdx := execTempFirstIndex
		for _, chunk := range chunksToWrite {
			ciphertext, envDesc, envHash, err := t.EncryptWrite(ctx, chunk, execTempWriteCap, execTempIdx)
			if err != nil {
				return err
			}
			_, err = t.StartResendingEncryptedMessage(ctx, nil, execTempWriteCap, nil, &replyIndex, envDesc, ciphertext, envHash)
			if err != nil {
				return err
			}
			execTempIdx, err = t.NextMessageBoxIndex(ctx, execTempIdx)
			if err != nil {
				return err
			}
		}

		// Issue CopyCommand with specified courier
		err = t.StartResendingCopyCommandWithCourier(ctx, execTempWriteCap, courier.IdentityHash, courier.QueueID)
		if err != nil {
			return err
		}

		// If not the last layer, read from intermediate for next iteration
		if cmdNum < depth-1 {
			nextLayerIdx := layerIdx - 1
			sourceIntermediate := intermediates[layerIdx-1]
			expectedBlob := layers[nextLayerIdx].blob

			var reconstructedStream []byte
			readIdx := sourceIntermediate.firstIndex
			for len(reconstructedStream) < len(expectedBlob) {
				ciphertext, nextIdx, envDesc, envHash, err := t.EncryptRead(ctx, sourceIntermediate.readCap, readIdx)
				if err != nil {
					return err
				}
				plaintext, err := t.StartResendingEncryptedMessage(ctx, sourceIntermediate.readCap, nil, nextIdx, &replyIndex, envDesc, ciphertext, envHash)
				if err != nil {
					return err
				}
				reconstructedStream = append(reconstructedStream, plaintext...)
				readIdx, err = t.NextMessageBoxIndex(ctx, readIdx)
				if err != nil {
					return err
				}
			}
			// Update the chunks for the next iteration (they're already built, we just needed to verify)
		}
	}

	return nil
}
