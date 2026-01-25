//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
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

	// Step 2: Alice encrypts a message using EncryptWrite
	t.Log("=== Step 2: Alice encrypts a message using EncryptWrite ===")
	aliceMessage := []byte("Bob, the eagle has landed. Rendezvous at dawn.")
	t.Logf("Alice: Original message: %q", aliceMessage)

	aliceWriteIndex, err := bacap.MessageBoxIndexFromBytes(aliceFirstIndex)
	require.NoError(t, err)

	aliceCiphertext, aliceEnvDesc, aliceEnvHash, aliceEpoch, err := aliceThinClient.EncryptWrite(ctx, aliceMessage, aliceWriteCap, aliceWriteIndex)
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
	t.Log("Waiting for message propagation to storage replicas (10 seconds)")
	time.Sleep(10 * time.Second)

	// Step 4: Bob encrypts a read request using EncryptRead
	t.Log("=== Step 4: Bob encrypts a read request using EncryptRead ===")
	bobReadIndex, err := bacap.MessageBoxIndexFromBytes(aliceFirstIndex)
	require.NoError(t, err)

	bobCiphertext, bobNextIndex, bobEnvDesc, bobEnvHash, bobEpoch, err := aliceThinClient.EncryptRead(ctx, bobReadCap, bobReadIndex)
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
		aliceWriteIndex, err := bacap.MessageBoxIndexFromBytes(aliceCurrentIndex)
		require.NoError(t, err)

		aliceCiphertext, aliceEnvDesc, aliceEnvHash, aliceEpoch, err := aliceThinClient.EncryptWrite(ctx, aliceMessage, aliceWriteCap, aliceWriteIndex)
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
		bobReadIndex, err := bacap.MessageBoxIndexFromBytes(bobCurrentIndex)
		require.NoError(t, err)

		bobCiphertext, bobNextIndex, bobEnvDesc, bobEnvHash, bobEpoch, err := aliceThinClient.EncryptRead(ctx, bobReadCap, bobReadIndex)
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

		// Advance state for next message
		t.Logf("Advancing state for next message")
		aliceWriteIndex.PrepareNext()
		aliceCurrentIndex = aliceWriteIndex.Bytes()

		bobReadIndex.PrepareNext()
		bobCurrentIndex = bobReadIndex.Bytes()

		// Cleanup: Cancel resending for this message
		err = aliceThinClient.CancelResendingEncryptedMessage(ctx, aliceEnvHash)
		require.NoError(t, err)

		err = bobThinClient.CancelResendingEncryptedMessage(ctx, bobEnvHash)
		require.NoError(t, err)
	}

	t.Logf("\n✓ SUCCESS: All %d messages sent and verified successfully!", numMessages)
}
