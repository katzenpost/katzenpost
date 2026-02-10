//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client2/constants"
)

// TestNewPigeonholeAPIAliceSendsBob tests the complete end-to-end flow of the new Pigeonhole API:
// 1. Alice creates a WriteCap and derives a ReadCap for Bob
// 2. Alice encrypts a message using EncryptWrite
// 3. Alice sends the encrypted message via StartResendingEncryptedMessage
// 4. Bob encrypts a read request using EncryptRead
// 5. Bob sends the read request and receives Alice's encrypted message
// 6. Bob decrypts Alice's message
//
// This test uses:
// - Real client2 daemon (via thin client)
// - Real courier server (running in Docker)
// - Real replica servers (running in Docker)
// - Real mixnet (running in Docker)
// - Real PKI (running in Docker)
// - Real Sphinx packets
// - Real PQ Noise wire protocol
func TestNewPigeonholeAPIAliceSendsBob(t *testing.T) {
	// Setup Alice and Bob thin clients
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	// Validate PKI documents
	currentDoc := validatePKIDocument(t, aliceThinClient)
	currentEpoch := currentDoc.Epoch
	bobDoc := validatePKIDocument(t, bobThinClient)
	require.Equal(t, currentEpoch, bobDoc.Epoch, "Alice and Bob must use same PKI epoch")
	t.Logf("Using PKI document for epoch %d", currentEpoch)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Step 1: Alice creates WriteCap and derives ReadCap for Bob using NewKeypair
	t.Log("=== Step 1: Alice creates WriteCap and derives ReadCap for Bob ===")
	aliceSeed := make([]byte, 32)
	_, err := rand.Reader.Read(aliceSeed)
	require.NoError(t, err)

	aliceWriteCap, bobReadCap, aliceFirstIndex, err := aliceThinClient.NewKeypair(ctx, aliceSeed)
	require.NoError(t, err)
	require.NotNil(t, aliceWriteCap, "Alice: WriteCap is nil")
	require.NotNil(t, bobReadCap, "Alice: ReadCap is nil")
	t.Log("Alice: Created WriteCap and derived ReadCap for Bob")

	// Verify that Alice's write box ID matches Bob's read box ID
	aliceBoxID := aliceFirstIndex.BoxIDForContext(aliceWriteCap.ReadCap(), constants.PIGEONHOLE_CTX)
	bobBoxID := aliceFirstIndex.BoxIDForContext(bobReadCap, constants.PIGEONHOLE_CTX)
	require.Equal(t, aliceBoxID.Bytes(), bobBoxID.Bytes(), "Box IDs must match: Alice's write box ID != Bob's read box ID")
	t.Logf("✓ Verified: Alice and Bob box IDs match: %x", aliceBoxID.Bytes())

	// Step 2: Alice encrypts a message using EncryptWrite
	t.Log("=== Step 2: Alice encrypts a message using EncryptWrite ===")
	// Make message bigger than 29 bytes to ensure courier returns ReplyTypePayload
	// (courier uses >29 byte threshold to distinguish between ACK and Payload replies)
	aliceMessage := []byte("Bob, the eagle has landed. Rendezvous at dawn. Bring the package and await further instructions.")
	t.Logf("Alice: Original message (%d bytes): %q", len(aliceMessage), aliceMessage)

	aliceCiphertext, aliceEnvDesc, aliceEnvHash, aliceEpoch, err := aliceThinClient.EncryptWrite(ctx, aliceMessage, aliceWriteCap, aliceFirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, aliceCiphertext, "Alice: EncryptWrite returned empty ciphertext")
	t.Logf("Alice: Encrypted message (%d bytes ciphertext)", len(aliceCiphertext))

	// Step 3: Alice sends the encrypted message via StartResendingEncryptedMessage
	t.Log("=== Step 3: Alice sends encrypted message to courier/replicas ===")
	replyIndex := uint8(0)
	alicePlaintext, err := aliceThinClient.StartResendingEncryptedMessage(
		ctx,
		nil,             // readCap (nil for write operations)
		aliceWriteCap,   // writeCap
		nil,             // nextMessageIndex (not needed for writes)
		&replyIndex,     // replyIndex
		aliceEnvDesc,    // envelopeDescriptor
		aliceCiphertext, // messageCiphertext
		aliceEnvHash,    // envelopeHash
		aliceEpoch,      // replicaEpoch
	)
	require.NoError(t, err)
	require.Empty(t, alicePlaintext, "Alice: Write operation should return empty plaintext")
	t.Log("Alice: Started resending encrypted write message")

	// Wait for message propagation to storage replicas
	t.Log("Waiting for message propagation to storage replicas (30 seconds)")
	time.Sleep(30 * time.Second)

	// Step 4: Bob encrypts a read request using EncryptRead
	t.Log("=== Step 4: Bob encrypts a read request using EncryptRead ===")

	bobCiphertext, bobNextIndex, bobEnvDesc, bobEnvHash, bobEpoch, err := bobThinClient.EncryptRead(ctx, bobReadCap, aliceFirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bobCiphertext, "Bob: EncryptRead returned empty ciphertext")
	t.Logf("Bob: Encrypted read request (%d bytes ciphertext)", len(bobCiphertext))

	// Step 5: Bob sends the read request and receives Alice's encrypted message
	t.Log("=== Step 5: Bob sends read request and receives encrypted message ===")
	bobPlaintext, err := bobThinClient.StartResendingEncryptedMessage(
		ctx,
		bobReadCap,    // readCap
		nil,           // writeCap (nil for read operations)
		bobNextIndex,  // nextMessageIndex
		&replyIndex,   // replyIndex
		bobEnvDesc,    // envelopeDescriptor
		bobCiphertext, // messageCiphertext
		bobEnvHash,    // envelopeHash
		bobEpoch,      // replicaEpoch
	)
	require.NoError(t, err)
	require.NotEmpty(t, bobPlaintext, "Bob: Failed to receive decrypted message")
	t.Logf("Bob: Received and decrypted message: %q", bobPlaintext)

	// Verify the decrypted message matches Alice's original message
	require.Equal(t, aliceMessage, bobPlaintext, "Message mismatch: Bob's decrypted message doesn't match Alice's original")
	t.Log("✓ SUCCESS: Bob successfully decrypted Alice's message!")

	// Cleanup: Cancel resending
	err = aliceThinClient.CancelResendingEncryptedMessage(ctx, aliceEnvHash)
	require.NoError(t, err)
	t.Log("Alice: Cancelled resending encrypted write message")

	err = bobThinClient.CancelResendingEncryptedMessage(ctx, bobEnvHash)
	require.NoError(t, err)
	t.Log("Bob: Cancelled resending encrypted read message")
}

// TestNewPigeonholeAPIMultipleMessages tests sending multiple sequential messages
// to verify that state management (PrepareNext/AdvanceState) works correctly
// in the real Docker environment.
func TestNewPigeonholeAPIMultipleMessages(t *testing.T) {
	// Setup Alice and Bob thin clients
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	// Validate PKI documents
	currentDoc := validatePKIDocument(t, aliceThinClient)
	currentEpoch := currentDoc.Epoch
	bobDoc := validatePKIDocument(t, bobThinClient)
	require.Equal(t, currentEpoch, bobDoc.Epoch, "Alice and Bob must use same PKI epoch")
	t.Logf("Using PKI document for epoch %d", currentEpoch)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	// Step 1: Alice creates WriteCap and derives ReadCap for Bob using NewKeypair
	t.Log("=== Setup: Alice creates WriteCap and derives ReadCap for Bob ===")
	aliceSeed := make([]byte, 32)
	_, err := rand.Reader.Read(aliceSeed)
	require.NoError(t, err)

	aliceWriteCap, bobReadCap, aliceFirstIndex, err := aliceThinClient.NewKeypair(ctx, aliceSeed)
	require.NoError(t, err)
	require.NotNil(t, aliceWriteCap, "Alice: WriteCap is nil")
	require.NotNil(t, bobReadCap, "Alice: ReadCap is nil")
	t.Log("Alice: Created WriteCap and derived ReadCap for Bob")

	// Send 3 sequential messages
	numMessages := 3
	messages := []string{
		"Message 1: The package has been delivered.",
		"Message 2: Proceed to the safe house.",
		"Message 3: Mission accomplished.",
	}

	// Track current indices for Alice and Bob
	aliceCurrentIndex := aliceFirstIndex
	bobCurrentIndex := aliceFirstIndex

	replyIndex := uint8(0)

	for i := 0; i < numMessages; i++ {
		t.Logf("\n=== Message %d/%d ===", i+1, numMessages)
		aliceMessage := []byte(messages[i])

		// Alice encrypts and sends message
		t.Logf("Alice: Encrypting message %d: %q", i+1, aliceMessage)

		aliceCiphertext, aliceEnvDesc, aliceEnvHash, aliceEpoch, err := aliceThinClient.EncryptWrite(ctx, aliceMessage, aliceWriteCap, aliceCurrentIndex)
		require.NoError(t, err)
		require.NotEmpty(t, aliceCiphertext, "Alice: EncryptWrite returned empty ciphertext for message %d", i+1)
		t.Logf("Alice: Encrypted message %d (%d bytes ciphertext)", i+1, len(aliceCiphertext))

		// Alice sends the encrypted message via StartResendingEncryptedMessage
		alicePlaintext, err := aliceThinClient.StartResendingEncryptedMessage(
			ctx,
			nil,             // readCap (nil for write operations)
			aliceWriteCap,   // writeCap
			nil,             // nextMessageIndex (not needed for writes)
			&replyIndex,     // replyIndex
			aliceEnvDesc,    // envelopeDescriptor
			aliceCiphertext, // messageCiphertext
			aliceEnvHash,    // envelopeHash
			aliceEpoch,      // replicaEpoch
		)
		require.NoError(t, err)
		require.Empty(t, alicePlaintext, "Alice: Write operation should return empty plaintext")
		t.Logf("Alice: Started resending message %d", i+1)

		// Wait for message propagation
		t.Logf("Waiting for message %d propagation (10 seconds)", i+1)
		time.Sleep(10 * time.Second)

		// Bob encrypts read request
		t.Logf("Bob: Encrypting read request for message %d", i+1)

		bobCiphertext, bobNextIndex, bobEnvDesc, bobEnvHash, bobEpoch, err := bobThinClient.EncryptRead(ctx, bobReadCap, bobCurrentIndex)
		require.NoError(t, err)
		require.NotEmpty(t, bobCiphertext, "Bob: EncryptRead returned empty ciphertext for message %d", i+1)
		t.Logf("Bob: Encrypted read request %d (%d bytes ciphertext)", i+1, len(bobCiphertext))

		// Bob sends read request and receives Alice's encrypted message
		bobPlaintext, err := bobThinClient.StartResendingEncryptedMessage(
			ctx,
			bobReadCap,    // readCap
			nil,           // writeCap (nil for read operations)
			bobNextIndex,  // nextMessageIndex
			&replyIndex,   // replyIndex
			bobEnvDesc,    // envelopeDescriptor
			bobCiphertext, // messageCiphertext
			bobEnvHash,    // envelopeHash
			bobEpoch,      // replicaEpoch
		)
		require.NoError(t, err)
		require.NotEmpty(t, bobPlaintext, "Bob: Failed to receive message %d", i+1)
		t.Logf("Bob: Received and decrypted message %d: %q", i+1, bobPlaintext)

		// Verify the decrypted message matches
		require.Equal(t, aliceMessage, bobPlaintext, "Message %d mismatch", i+1)
		t.Logf("✓ Message %d verified successfully!", i+1)

		// Advance state for next message using thin client API
		t.Logf("Advancing state for next message")
		aliceCurrentIndex, err = aliceThinClient.NextMessageBoxIndex(ctx, aliceCurrentIndex)
		require.NoError(t, err)

		bobCurrentIndex, err = bobThinClient.NextMessageBoxIndex(ctx, bobCurrentIndex)
		require.NoError(t, err)

		// Cleanup: Cancel resending for this message
		err = aliceThinClient.CancelResendingEncryptedMessage(ctx, aliceEnvHash)
		require.NoError(t, err)

		err = bobThinClient.CancelResendingEncryptedMessage(ctx, bobEnvHash)
		require.NoError(t, err)
	}

	t.Logf("\n✓ SUCCESS: All %d messages sent and verified successfully!", numMessages)
}

// TestCopyChannelAPI tests the Copy Channel API end-to-end:
// 1. Alice creates multiple CourierEnvelopes for different write operations
// 2. Alice writes all CourierEnvelopes to a temporary copy stream
// 3. Alice sends the Copy command to the courier with the temp WriteCap
// 4. Courier executes all writes atomically to the destination channel
// 5. Bob reads all messages from the destination channel
//
// This test verifies:
// - CreateCourierEnvelope creates valid envelopes
// - Envelopes can be written to a temporary copy stream
// - SendCopyCommand successfully triggers the courier's copy operation
// - All writes are executed atomically (all-or-nothing)
// - Bob can read all messages that were written via the Copy command
func TestCopyChannelAPI(t *testing.T) {
	// Setup Alice and Bob thin clients
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	// Validate PKI documents
	currentDoc := validatePKIDocument(t, aliceThinClient)
	currentEpoch := currentDoc.Epoch
	bobDoc := validatePKIDocument(t, bobThinClient)
	require.Equal(t, currentEpoch, bobDoc.Epoch, "Alice and Bob must use same PKI epoch")
	t.Logf("Using PKI document for epoch %d", currentEpoch)

	// Find courier service
	courierDesc, ok := currentDoc.ServiceNodes[0].Kaetzchen["courier"]
	require.True(t, ok, "Courier service not found in PKI document")
	courierNodeIDHash := hash.Sum256(currentDoc.ServiceNodes[0].IdentityKey)
	courierQueueID := courierDesc.RecipientQueueID
	t.Logf("Found courier service at node %x, queue %s", courierNodeIDHash[:8], courierQueueID)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	// Step 1: Alice creates destination WriteCap for the final messages
	t.Log("=== Step 1: Alice creates destination WriteCap ===")
	destSeed := make([]byte, 32)
	_, err := rand.Reader.Read(destSeed)
	require.NoError(t, err)

	destWriteCap, bobReadCap, destFirstIndex, err := aliceThinClient.NewKeypair(ctx, destSeed)
	require.NoError(t, err)
	require.NotNil(t, destWriteCap, "Destination WriteCap is nil")
	require.NotNil(t, bobReadCap, "Bob ReadCap is nil")
	t.Log("Alice: Created destination WriteCap and derived ReadCap for Bob")

	// Step 2: Alice creates temporary copy stream
	t.Log("=== Step 2: Alice creates temporary copy stream ===")
	tempSeed := make([]byte, 32)
	_, err = rand.Reader.Read(tempSeed)
	require.NoError(t, err)

	tempWriteCap, _, tempFirstIndex, err := aliceThinClient.NewKeypair(ctx, tempSeed)
	require.NoError(t, err)
	require.NotNil(t, tempWriteCap, "Temp WriteCap is nil")
	t.Log("Alice: Created temporary copy stream WriteCap")

	// Step 3: Create multiple messages and CourierEnvelopes
	t.Log("=== Step 3: Creating CourierEnvelopes for multiple messages ===")
	messages := []string{
		"Message 1: The package has been delivered.",
		"Message 2: Proceed to the safe house.",
		"Message 3: Mission accomplished.",
	}
	numMessages := len(messages)

	destIndex := destFirstIndex
	tempIndex := tempFirstIndex
	replyIndex := uint8(0)

	for i := 0; i < numMessages; i++ {
		t.Logf("\n--- Creating CourierEnvelope %d/%d ---", i+1, numMessages)
		message := []byte(messages[i])

		// Create CourierEnvelope for this write operation
		courierEnvelope, err := aliceThinClient.CreateCourierEnvelope(ctx, message, destWriteCap, destIndex)
		require.NoError(t, err)
		require.NotEmpty(t, courierEnvelope, "CreateCourierEnvelope returned empty envelope")
		t.Logf("Alice: Created CourierEnvelope %d (%d bytes)", i+1, len(courierEnvelope))

		// Write the CourierEnvelope to the temporary copy stream
		ciphertext, envDesc, envHash, epoch, err := aliceThinClient.EncryptWrite(ctx, courierEnvelope, tempWriteCap, tempIndex)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext, "EncryptWrite returned empty ciphertext")
		t.Logf("Alice: Encrypted CourierEnvelope %d for copy stream (%d bytes ciphertext)", i+1, len(ciphertext))

		// Send the encrypted CourierEnvelope to the copy stream
		_, err = aliceThinClient.StartResendingEncryptedMessage(
			ctx, nil, tempWriteCap, tempIndex.Bytes(), &replyIndex,
			envDesc, ciphertext, envHash, epoch)
		require.NoError(t, err)
		t.Logf("Alice: Sent CourierEnvelope %d to copy stream", i+1)

		// Increment indices for next message
		destIndex, err = aliceThinClient.NextMessageBoxIndex(ctx, destIndex)
		require.NoError(t, err)

		tempIndex, err = aliceThinClient.NextMessageBoxIndex(ctx, tempIndex)
		require.NoError(t, err)

		// Cancel resending for this envelope
		err = aliceThinClient.CancelResendingEncryptedMessage(ctx, envHash)
		require.NoError(t, err)
	}

	// Wait for all envelopes to propagate to the copy stream
	t.Log("Waiting for CourierEnvelopes to propagate to copy stream (30 seconds)")
	time.Sleep(30 * time.Second)

	// Step 4: Send Copy command to courier
	t.Log("=== Step 4: Sending Copy command to courier ===")
	errorCode, err := aliceThinClient.SendCopyCommand(ctx, tempWriteCap, &courierNodeIDHash, courierQueueID)
	require.NoError(t, err)
	require.Equal(t, uint8(0), errorCode, "Copy command returned error code %d", errorCode)
	t.Log("Alice: Copy command sent successfully, courier will execute all writes atomically")

	// Wait for courier to execute the copy command
	t.Log("Waiting for courier to execute Copy command (30 seconds)")
	time.Sleep(30 * time.Second)

	// Step 5: Bob reads all messages from the destination channel
	t.Log("=== Step 5: Bob reads all messages from destination channel ===")
	bobIndex := destFirstIndex

	for i := 0; i < numMessages; i++ {
		t.Logf("\n--- Bob reading message %d/%d ---", i+1, numMessages)

		// Bob encrypts read request
		bobCiphertext, bobNextIndex, bobEnvDesc, bobEnvHash, bobEpoch, err := bobThinClient.EncryptRead(ctx, bobReadCap, bobIndex)
		require.NoError(t, err)
		require.NotEmpty(t, bobCiphertext, "Bob: EncryptRead returned empty ciphertext")
		t.Logf("Bob: Encrypted read request %d", i+1)

		// Bob sends read request and receives message
		bobPlaintext, err := bobThinClient.StartResendingEncryptedMessage(
			ctx, bobReadCap, nil, bobNextIndex, &replyIndex,
			bobEnvDesc, bobCiphertext, bobEnvHash, bobEpoch)
		require.NoError(t, err)
		require.NotEmpty(t, bobPlaintext, "Bob: Failed to receive message %d", i+1)
		t.Logf("Bob: Received and decrypted message %d: %q", i+1, bobPlaintext)

		// Verify the message matches
		expectedMessage := []byte(messages[i])
		require.Equal(t, expectedMessage, bobPlaintext, "Message %d mismatch", i+1)
		t.Logf("✓ Message %d verified successfully!", i+1)

		// Advance to next message
		bobIndex, err = bobThinClient.NextMessageBoxIndex(ctx, bobIndex)
		require.NoError(t, err)

		// Cancel resending
		err = bobThinClient.CancelResendingEncryptedMessage(ctx, bobEnvHash)
		require.NoError(t, err)
	}

	t.Logf("\n✓ SUCCESS: Copy Channel API test passed! All %d messages written atomically and read successfully!", numMessages)
}
