// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"bytes"
	"context"
	"errors"

	"github.com/katzenpost/hpqc/bacap"
)

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
// For all operations, this method first waits for an ACK reply from the courier.
// For read operations (readCap != nil), after receiving the ACK, it automatically
// requests the payload data by incrementing the replyIndex.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - readCap: Read capability (can be nil for write operations)
//   - writeCap: Write capability (can be nil for read operations)
//   - nextMessageIndex: Next message index for subsequent operations
//   - replyIndex: Index of the reply to use (typically 0 or 1)
//   - envelopeDescriptor: Serialized envelope descriptor for decryption
//   - messageCiphertext: Encrypted message to send
//   - envelopeHash: Hash of the courier envelope
//   - replicaEpoch: Epoch when the envelope was created
//
// Returns:
//   - []byte: Decrypted plaintext from the reply (for reads) or empty (for writes)
//   - error: Any error encountered during the operation
//
// Example:
//
//	ctx := context.Background()
//	plaintext, err := client.StartResendingEncryptedMessage(
//		ctx, readCap, nil, nextIndex, &replyIdx, envDesc, ciphertext, envHash, epoch)
//	if err != nil {
//		log.Fatal("Failed to start resending:", err)
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

	// Step 1: Send request and wait for ACK
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

	// Wait for ACK reply
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
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}

			// For write operations, ACK is the final reply
			if !isRead {
				t.log.Debugf("StartResendingEncryptedMessage: Write operation - received ACK, returning empty plaintext")
				return v.Plaintext, nil
			}

			// For read operations, ACK should be empty - now request the payload
			t.log.Debugf("StartResendingEncryptedMessage: Read operation - received ACK (len=%d), now requesting payload", len(v.Plaintext))

			// Step 2: For reads, increment replyIndex and request the payload
			nextReplyIndex := *replyIndex + 1
			t.log.Debugf("StartResendingEncryptedMessage: Requesting payload with replyIndex=%d", nextReplyIndex)

			queryID2 := t.NewQueryID()
			req2 := &Request{
				StartResendingEncryptedMessage: &StartResendingEncryptedMessage{
					QueryID:            queryID2,
					ReadCap:            readCap,
					WriteCap:           writeCap,
					NextMessageIndex:   nextMessageIndex,
					ReplyIndex:         &nextReplyIndex,
					EnvelopeDescriptor: envelopeDescriptor,
					MessageCiphertext:  messageCiphertext,
					EnvelopeHash:       envelopeHash,
					ReplicaEpoch:       replicaEpoch,
				},
			}

			err := t.writeMessage(req2)
			if err != nil {
				return nil, err
			}

			// Wait for payload reply
			for {
				var event2 Event
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case event2 = <-eventSink:
				case <-t.HaltCh():
					return nil, errHalting
				}

				switch v2 := event2.(type) {
				case *StartResendingEncryptedMessageReply:
					if v2.QueryID == nil {
						t.log.Debugf("StartResendingEncryptedMessage: Received payload reply with nil QueryID, ignoring")
						continue
					}
					if !bytes.Equal(v2.QueryID[:], queryID2[:]) {
						t.log.Debugf("StartResendingEncryptedMessage: Received payload reply with mismatched QueryID, ignoring")
						continue
					}
					if v2.ErrorCode != ThinClientSuccess {
						return nil, errors.New(ThinClientErrorToString(v2.ErrorCode))
					}

					t.log.Debugf("StartResendingEncryptedMessage: Read operation - received payload (len=%d)", len(v2.Plaintext))
					return v2.Plaintext, nil
				case *ConnectionStatusEvent:
					t.isConnected = v2.IsConnected
				case *NewDocumentEvent:
					// Ignore PKI document updates
				default:
					// Ignore other events
				}
			}

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
