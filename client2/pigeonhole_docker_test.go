//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/client2/thin"
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

	// Validate PKI documents - use Alice's epoch for Bob to avoid race condition at epoch boundary
	aliceDoc := validatePKIDocument(t, aliceThinClient)
	currentEpoch := aliceDoc.Epoch
	bobDoc := validatePKIDocumentForEpoch(t, bobThinClient, currentEpoch)
	require.Equal(t, aliceDoc.Sum256(), bobDoc.Sum256(), "Alice and Bob must have the same PKI document")
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

	aliceCiphertext, aliceEnvDesc, aliceEnvHash, err := aliceThinClient.EncryptWrite(ctx, aliceMessage, aliceWriteCap, aliceFirstIndex)
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
	)
	require.NoError(t, err)
	require.Empty(t, alicePlaintext, "Alice: Write operation should return empty plaintext")
	t.Log("Alice: Started resending encrypted write message")

	// Wait for message propagation to storage replicas
	t.Log("Waiting for message propagation to storage replicas (30 seconds)")
	time.Sleep(30 * time.Second)

	// Step 4: Bob encrypts a read request using EncryptRead
	t.Log("=== Step 4: Bob encrypts a read request using EncryptRead ===")

	bobCiphertext, bobNextIndex, bobEnvDesc, bobEnvHash, err := bobThinClient.EncryptRead(ctx, bobReadCap, aliceFirstIndex)
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
	)
	require.NoError(t, err)
	require.NotEmpty(t, bobPlaintext, "Bob: Failed to receive decrypted message")
	t.Logf("Bob: Received and decrypted message: %q", bobPlaintext)

	// Verify the decrypted message matches Alice's original message
	require.Equal(t, aliceMessage, bobPlaintext, "Message mismatch: Bob's decrypted message doesn't match Alice's original")
	t.Log("✓ SUCCESS: Bob successfully decrypted Alice's message!")
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

	// Validate PKI documents - use Alice's epoch for Bob to avoid race condition at epoch boundary
	aliceDoc := validatePKIDocument(t, aliceThinClient)
	currentEpoch := aliceDoc.Epoch
	bobDoc := validatePKIDocumentForEpoch(t, bobThinClient, currentEpoch)
	require.Equal(t, aliceDoc.Sum256(), bobDoc.Sum256(), "Alice and Bob must have the same PKI document")
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

		aliceCiphertext, aliceEnvDesc, aliceEnvHash, err := aliceThinClient.EncryptWrite(ctx, aliceMessage, aliceWriteCap, aliceCurrentIndex)
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
		)
		require.NoError(t, err)
		require.Empty(t, alicePlaintext, "Alice: Write operation should return empty plaintext")
		t.Logf("Alice: Started resending message %d", i+1)

		// Wait for message propagation
		t.Logf("Waiting for message %d propagation (10 seconds)", i+1)
		time.Sleep(10 * time.Second)

		// Bob encrypts read request
		t.Logf("Bob: Encrypting read request for message %d", i+1)

		bobCiphertext, bobNextIndex, bobEnvDesc, bobEnvHash, err := bobThinClient.EncryptRead(ctx, bobReadCap, bobCurrentIndex)
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
	}

	t.Logf("\n✓ SUCCESS: All %d messages sent and verified successfully!", numMessages)
}

// TestCreateCourierEnvelopesFromPayload tests the CreateCourierEnvelopesFromPayload API:
// 1. Alice creates a large payload that will be automatically chunked
// 2. Alice calls CreateCourierEnvelopesFromPayload to get copy stream chunks
// 3. Alice writes all copy stream chunks to a temporary copy stream channel
// 4. Alice sends the Copy command to the courier
// 5. Bob reads all chunks from the destination channel and reconstructs the payload
//
// This test verifies:
// - CreateCourierEnvelopesFromPayload correctly chunks large payloads and encodes them in copy stream format
// - Copy stream chunks can be written to a temporary channel
// - The Copy Channel API works with the copy stream format
// - The courier can decode the copy stream and execute all writes atomically
// - Bob can read and reconstruct the original large payload
func TestCreateCourierEnvelopesFromPayload(t *testing.T) {
	// Setup Alice and Bob thin clients
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	// Validate PKI documents - use Alice's epoch for Bob to avoid race condition at epoch boundary
	aliceDoc := validatePKIDocument(t, aliceThinClient)
	currentEpoch := aliceDoc.Epoch
	bobDoc := validatePKIDocumentForEpoch(t, bobThinClient, currentEpoch)
	require.Equal(t, aliceDoc.Sum256(), bobDoc.Sum256(), "Alice and Bob must have the same PKI document")
	t.Logf("Using PKI document for epoch %d", currentEpoch)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	// Step 1: Alice creates destination WriteCap for the final payload
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

	// Step 3: Create a large payload that will be chunked
	t.Log("=== Step 3: Creating large payload ===")
	// Create a payload large enough to require multiple chunks
	// Actual chunk count depends on pigeonhole geometry
	// Use a 4-byte length prefix so Bob knows when to stop reading
	randomData := make([]byte, 5*1024)
	_, err = rand.Reader.Read(randomData)
	require.NoError(t, err)
	// Length-prefix the payload: [4 bytes length][random data]
	largePayload := make([]byte, 4+len(randomData))
	binary.BigEndian.PutUint32(largePayload[:4], uint32(len(randomData)))
	copy(largePayload[4:], randomData)
	t.Logf("Alice: Created large payload (%d bytes = 4 byte length prefix + %d bytes data)", len(largePayload), len(randomData))

	// Step 4: Create copy stream chunks from the large payload
	t.Log("=== Step 4: Creating copy stream chunks from large payload ===")
	streamID := aliceThinClient.NewStreamID()
	copyStreamChunks, err := aliceThinClient.CreateCourierEnvelopesFromPayload(ctx, streamID, largePayload, destWriteCap, destFirstIndex, true /* isLast */)
	require.NoError(t, err)
	require.NotEmpty(t, copyStreamChunks, "CreateCourierEnvelopesFromPayload returned empty chunks")
	numChunks := len(copyStreamChunks)
	t.Logf("Alice: Created %d copy stream chunks from %d byte payload", numChunks, len(largePayload))

	// Print the destination box IDs for each chunk
	t.Log("=== Destination Box IDs ===")
	currentDestIndex := destFirstIndex
	for i := 0; i < numChunks; i++ {
		boxID := currentDestIndex.BoxIDForContext(bobReadCap, constants.PIGEONHOLE_CTX)
		t.Logf("Chunk %d/%d: Box ID = %x", i+1, numChunks, boxID.Bytes())
		currentDestIndex, err = aliceThinClient.NextMessageBoxIndex(ctx, currentDestIndex)
		require.NoError(t, err)
	}

	// Step 5: Write all copy stream chunks to the temporary copy stream
	t.Log("=== Step 5: Writing copy stream chunks to temporary channel ===")
	tempIndex := tempFirstIndex
	replyIndex := uint8(0)

	for i, chunk := range copyStreamChunks {
		t.Logf("--- Writing copy stream chunk %d/%d to temporary channel ---", i+1, numChunks)

		// Encrypt the chunk for the copy stream
		ciphertext, envDesc, envHash, err := aliceThinClient.EncryptWrite(ctx, chunk, tempWriteCap, tempIndex)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext, "EncryptWrite returned empty ciphertext for chunk %d", i+1)
		t.Logf("Alice: Encrypted copy stream chunk %d (%d bytes plaintext -> %d bytes ciphertext)", i+1, len(chunk), len(ciphertext))

		// Send the encrypted chunk to the copy stream
		_, err = aliceThinClient.StartResendingEncryptedMessage(
			ctx, nil, tempWriteCap, nil, &replyIndex,
			envDesc, ciphertext, envHash)
		require.NoError(t, err)
		t.Logf("Alice: Sent copy stream chunk %d to temporary channel", i+1)

		// Increment temp index for next chunk
		tempIndex, err = aliceThinClient.NextMessageBoxIndex(ctx, tempIndex)
		require.NoError(t, err)
	}

	// Wait for all chunks to propagate to the copy stream
	t.Log("Waiting for copy stream chunks to propagate to temporary channel (30 seconds)")
	time.Sleep(30 * time.Second)

	// Step 6: Send Copy command to courier using ARQ
	t.Log("=== Step 6: Sending Copy command to courier via ARQ ===")
	t.Log("Alice: Sending Copy command to courier using StartResendingCopyCommand (ARQ)...")
	err = aliceThinClient.StartResendingCopyCommand(ctx, tempWriteCap)
	require.NoError(t, err)
	t.Log("Alice: Copy command completed successfully via ARQ")

	// Step 7: Bob reads chunks until we have the full payload (based on length prefix)
	t.Log("=== Step 7: Bob reads all chunks and reconstructs payload ===")
	bobIndex := destFirstIndex
	var reconstructedPayload []byte
	var expectedLength uint32
	chunkNum := 0

	for {
		chunkNum++
		t.Logf("--- Bob reading chunk %d ---", chunkNum)

		// Bob encrypts read request
		bobCiphertext, bobNextIndex, bobEnvDesc, bobEnvHash, err := bobThinClient.EncryptRead(ctx, bobReadCap, bobIndex)
		require.NoError(t, err)
		require.NotEmpty(t, bobCiphertext, "Bob: EncryptRead returned empty ciphertext")
		t.Logf("Bob: Encrypted read request %d", chunkNum)

		// Bob sends read request and receives chunk
		bobPlaintext, err := bobThinClient.StartResendingEncryptedMessage(
			ctx, bobReadCap, nil, bobNextIndex, &replyIndex,
			bobEnvDesc, bobCiphertext, bobEnvHash)
		require.NoError(t, err)
		require.NotEmpty(t, bobPlaintext, "Bob: Failed to receive chunk %d", chunkNum)
		t.Logf("Bob: Received and decrypted chunk %d (%d bytes)", chunkNum, len(bobPlaintext))

		// Append chunk to reconstructed payload
		reconstructedPayload = append(reconstructedPayload, bobPlaintext...)

		// Extract expected length from the first 4 bytes once we have them
		if expectedLength == 0 && len(reconstructedPayload) >= 4 {
			expectedLength = binary.BigEndian.Uint32(reconstructedPayload[:4])
			t.Logf("Bob: Expected payload length is %d bytes (+ 4 byte prefix = %d total)", expectedLength, expectedLength+4)
		}

		// Check if we have the full payload (4 byte prefix + expectedLength bytes)
		if expectedLength > 0 && uint32(len(reconstructedPayload)) >= expectedLength+4 {
			t.Logf("Bob: Received full payload after %d chunks", chunkNum)
			break
		}

		// Advance to next chunk
		bobIndex, err = bobThinClient.NextMessageBoxIndex(ctx, bobIndex)
		require.NoError(t, err)
	}

	// Verify the reconstructed payload matches the original
	t.Logf("Bob: Reconstructed payload (%d bytes)", len(reconstructedPayload))
	require.Equal(t, largePayload, reconstructedPayload, "Reconstructed payload doesn't match original")
	t.Logf("\n✓ SUCCESS: CreateCourierEnvelopesFromPayload test passed! Large payload (%d bytes data) encoded into %d copy stream chunks and reconstructed successfully!", len(randomData), numChunks)
}

// TestCopyCommandMultiChannel tests the Copy Command API with multiple destination channels:
// 1. Alice creates two destination channels (chan1 and chan2)
// 2. Alice creates a temporary copy stream channel
// 3. Alice creates two payloads - one for each destination channel
// 4. Alice calls CreateCourierEnvelopesFromPayload twice with the same streamID but different WriteCaps
// 5. Alice writes all copy stream chunks to the temporary channel
// 6. Alice sends the Copy command to the courier
// 7. Bob reads from both destination channels and verifies the payloads
//
// This test verifies:
// - The Copy Command API can atomically write to multiple destination channels
// - Multiple calls to CreateCourierEnvelopesFromPayload with the same streamID work correctly
// - The courier processes all envelopes and writes to the correct destinations
func TestCopyCommandMultiChannel(t *testing.T) {
	// Setup Alice and Bob thin clients
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	// Validate PKI documents
	aliceDoc := validatePKIDocument(t, aliceThinClient)
	currentEpoch := aliceDoc.Epoch
	bobDoc := validatePKIDocumentForEpoch(t, bobThinClient, currentEpoch)
	require.Equal(t, aliceDoc.Sum256(), bobDoc.Sum256(), "Alice and Bob must have the same PKI document")
	t.Logf("Using PKI document for epoch %d", currentEpoch)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	// Step 1: Alice creates two destination channels
	t.Log("=== Step 1: Alice creates two destination channels ===")

	// Channel 1
	chan1Seed := make([]byte, 32)
	_, err := rand.Reader.Read(chan1Seed)
	require.NoError(t, err)
	chan1WriteCap, chan1ReadCap, chan1FirstIndex, err := aliceThinClient.NewKeypair(ctx, chan1Seed)
	require.NoError(t, err)
	require.NotNil(t, chan1WriteCap, "Channel 1 WriteCap is nil")
	require.NotNil(t, chan1ReadCap, "Channel 1 ReadCap is nil")
	t.Log("Alice: Created Channel 1 (WriteCap and ReadCap)")

	// Channel 2
	chan2Seed := make([]byte, 32)
	_, err = rand.Reader.Read(chan2Seed)
	require.NoError(t, err)
	chan2WriteCap, chan2ReadCap, chan2FirstIndex, err := aliceThinClient.NewKeypair(ctx, chan2Seed)
	require.NoError(t, err)
	require.NotNil(t, chan2WriteCap, "Channel 2 WriteCap is nil")
	require.NotNil(t, chan2ReadCap, "Channel 2 ReadCap is nil")
	t.Log("Alice: Created Channel 2 (WriteCap and ReadCap)")

	// Step 2: Alice creates temporary copy stream
	t.Log("=== Step 2: Alice creates temporary copy stream ===")
	tempSeed := make([]byte, 32)
	_, err = rand.Reader.Read(tempSeed)
	require.NoError(t, err)
	tempWriteCap, _, tempFirstIndex, err := aliceThinClient.NewKeypair(ctx, tempSeed)
	require.NoError(t, err)
	require.NotNil(t, tempWriteCap, "Temp WriteCap is nil")
	t.Log("Alice: Created temporary copy stream WriteCap")

	// Step 3: Create two payloads - one for each destination channel
	t.Log("=== Step 3: Creating payloads for each channel ===")

	// Payload 1 for Channel 1
	payload1 := []byte("This is the secret message for Channel 1. It contains important information.")
	t.Logf("Alice: Created payload1 for Channel 1 (%d bytes)", len(payload1))

	// Payload 2 for Channel 2
	payload2 := []byte("This is the confidential data for Channel 2. Handle with care and discretion.")
	t.Logf("Alice: Created payload2 for Channel 2 (%d bytes)", len(payload2))

	// Step 4: Create copy stream chunks using same streamID but different WriteCaps
	t.Log("=== Step 4: Creating copy stream chunks for both channels ===")
	streamID := aliceThinClient.NewStreamID()

	// First call: payload1 -> channel 1 (isLast=false)
	chunks1, err := aliceThinClient.CreateCourierEnvelopesFromPayload(ctx, streamID, payload1, chan1WriteCap, chan1FirstIndex, false)
	require.NoError(t, err)
	require.NotEmpty(t, chunks1, "CreateCourierEnvelopesFromPayload returned empty chunks for channel 1")
	t.Logf("Alice: Created %d chunks for Channel 1", len(chunks1))

	// Second call: payload2 -> channel 2 (isLast=true)
	chunks2, err := aliceThinClient.CreateCourierEnvelopesFromPayload(ctx, streamID, payload2, chan2WriteCap, chan2FirstIndex, true)
	require.NoError(t, err)
	require.NotEmpty(t, chunks2, "CreateCourierEnvelopesFromPayload returned empty chunks for channel 2")
	t.Logf("Alice: Created %d chunks for Channel 2", len(chunks2))

	// Combine all chunks
	allChunks := append(chunks1, chunks2...)
	t.Logf("Alice: Total chunks to write to temp channel: %d", len(allChunks))

	// Step 5: Write all copy stream chunks to the temporary channel
	t.Log("=== Step 5: Writing all chunks to temporary channel ===")
	tempIndex := tempFirstIndex
	replyIndex := uint8(0)

	for i, chunk := range allChunks {
		t.Logf("--- Writing chunk %d/%d to temporary channel ---", i+1, len(allChunks))

		// Encrypt the chunk for the copy stream
		ciphertext, envDesc, envHash, err := aliceThinClient.EncryptWrite(ctx, chunk, tempWriteCap, tempIndex)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext, "EncryptWrite returned empty ciphertext for chunk %d", i+1)
		t.Logf("Alice: Encrypted chunk %d (%d bytes plaintext -> %d bytes ciphertext)", i+1, len(chunk), len(ciphertext))

		// Send the encrypted chunk to the copy stream
		_, err = aliceThinClient.StartResendingEncryptedMessage(
			ctx, nil, tempWriteCap, nil, &replyIndex,
			envDesc, ciphertext, envHash)
		require.NoError(t, err)
		t.Logf("Alice: Sent chunk %d to temporary channel", i+1)

		// Increment temp index for next chunk
		tempIndex, err = aliceThinClient.NextMessageBoxIndex(ctx, tempIndex)
		require.NoError(t, err)
	}

	// Wait for chunks to propagate
	t.Log("Waiting for copy stream chunks to propagate (30 seconds)")
	time.Sleep(30 * time.Second)

	// Step 6: Send Copy command to courier using ARQ
	t.Log("=== Step 6: Sending Copy command to courier via ARQ ===")
	err = aliceThinClient.StartResendingCopyCommand(ctx, tempWriteCap)
	require.NoError(t, err)
	t.Log("Alice: Copy command completed successfully via ARQ")

	// Step 7: Bob reads from both channels and verifies payloads
	t.Log("=== Step 7: Bob reads from both channels ===")

	// Read from Channel 1
	t.Log("--- Bob reading from Channel 1 ---")
	bob1Ciphertext, bob1NextIndex, bob1EnvDesc, bob1EnvHash, err := bobThinClient.EncryptRead(ctx, chan1ReadCap, chan1FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 1")

	bob1Plaintext, err := bobThinClient.StartResendingEncryptedMessage(
		ctx, chan1ReadCap, nil, bob1NextIndex, &replyIndex,
		bob1EnvDesc, bob1Ciphertext, bob1EnvHash)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Plaintext, "Bob: Failed to receive data from Channel 1")
	t.Logf("Bob: Received from Channel 1: %q (%d bytes)", bob1Plaintext, len(bob1Plaintext))

	// Verify Channel 1 payload
	require.Equal(t, payload1, bob1Plaintext, "Channel 1 payload doesn't match")
	t.Log("✓ Channel 1 payload verified!")

	// Read from Channel 2
	t.Log("--- Bob reading from Channel 2 ---")
	bob2Ciphertext, bob2NextIndex, bob2EnvDesc, bob2EnvHash, err := bobThinClient.EncryptRead(ctx, chan2ReadCap, chan2FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 2")

	bob2Plaintext, err := bobThinClient.StartResendingEncryptedMessage(
		ctx, chan2ReadCap, nil, bob2NextIndex, &replyIndex,
		bob2EnvDesc, bob2Ciphertext, bob2EnvHash)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Plaintext, "Bob: Failed to receive data from Channel 2")
	t.Logf("Bob: Received from Channel 2: %q (%d bytes)", bob2Plaintext, len(bob2Plaintext))

	// Verify Channel 2 payload
	require.Equal(t, payload2, bob2Plaintext, "Channel 2 payload doesn't match")
	t.Log("✓ Channel 2 payload verified!")

	t.Log("\n✓ SUCCESS: Multi-channel Copy Command test passed! Payload1 written to Channel 1 and Payload2 written to Channel 2 atomically!")
}

// TestCopyCommandMultiChannelEfficient tests the space-efficient multi-channel copy command
// using CreateCourierEnvelopesFromPayloads which packs envelopes from different destinations
// together without wasting space in the copy stream.
//
// This test verifies:
// - The CreateCourierEnvelopesFromPayloads API works correctly
// - Multiple destination payloads are packed efficiently into the copy stream
// - The courier processes all envelopes and writes to the correct destinations
func TestCopyCommandMultiChannelEfficient(t *testing.T) {
	// Setup Alice and Bob thin clients
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	// Validate PKI documents
	aliceDoc := validatePKIDocument(t, aliceThinClient)
	currentEpoch := aliceDoc.Epoch
	bobDoc := validatePKIDocumentForEpoch(t, bobThinClient, currentEpoch)
	require.Equal(t, aliceDoc.Sum256(), bobDoc.Sum256(), "Alice and Bob must have the same PKI document")
	t.Logf("Using PKI document for epoch %d", currentEpoch)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	// Step 1: Alice creates two destination channels
	t.Log("=== Step 1: Alice creates two destination channels ===")

	// Channel 1
	chan1Seed := make([]byte, 32)
	_, err := rand.Reader.Read(chan1Seed)
	require.NoError(t, err)
	chan1WriteCap, chan1ReadCap, chan1FirstIndex, err := aliceThinClient.NewKeypair(ctx, chan1Seed)
	require.NoError(t, err)
	require.NotNil(t, chan1WriteCap, "Channel 1 WriteCap is nil")
	require.NotNil(t, chan1ReadCap, "Channel 1 ReadCap is nil")
	t.Log("Alice: Created Channel 1 (WriteCap and ReadCap)")

	// Channel 2
	chan2Seed := make([]byte, 32)
	_, err = rand.Reader.Read(chan2Seed)
	require.NoError(t, err)
	chan2WriteCap, chan2ReadCap, chan2FirstIndex, err := aliceThinClient.NewKeypair(ctx, chan2Seed)
	require.NoError(t, err)
	require.NotNil(t, chan2WriteCap, "Channel 2 WriteCap is nil")
	require.NotNil(t, chan2ReadCap, "Channel 2 ReadCap is nil")
	t.Log("Alice: Created Channel 2 (WriteCap and ReadCap)")

	// Step 2: Alice creates temporary copy stream
	t.Log("=== Step 2: Alice creates temporary copy stream ===")
	tempSeed := make([]byte, 32)
	_, err = rand.Reader.Read(tempSeed)
	require.NoError(t, err)
	tempWriteCap, _, tempFirstIndex, err := aliceThinClient.NewKeypair(ctx, tempSeed)
	require.NoError(t, err)
	require.NotNil(t, tempWriteCap, "Temp WriteCap is nil")
	t.Log("Alice: Created temporary copy stream WriteCap")

	// Step 3: Create two payloads - one for each destination channel
	t.Log("=== Step 3: Creating payloads for each channel ===")

	// Payload 1 for Channel 1
	payload1 := []byte("This is the secret message for Channel 1 using the efficient multi-channel API.")
	t.Logf("Alice: Created payload1 for Channel 1 (%d bytes)", len(payload1))

	// Payload 2 for Channel 2
	payload2 := []byte("This is the confidential data for Channel 2 packed efficiently with payload1.")
	t.Logf("Alice: Created payload2 for Channel 2 (%d bytes)", len(payload2))

	// Step 4: Create copy stream chunks using CreateCourierEnvelopesFromPayloads (efficient API)
	t.Log("=== Step 4: Creating copy stream chunks using efficient multi-destination API ===")
	streamID := aliceThinClient.NewStreamID()

	// Create destinations slice with both payloads
	destinations := []thin.DestinationPayload{
		{
			Payload:    payload1,
			WriteCap:   chan1WriteCap,
			StartIndex: chan1FirstIndex,
		},
		{
			Payload:    payload2,
			WriteCap:   chan2WriteCap,
			StartIndex: chan2FirstIndex,
		},
	}

	// Single call packs all envelopes efficiently
	allChunks, err := aliceThinClient.CreateCourierEnvelopesFromPayloads(ctx, streamID, destinations, true)
	require.NoError(t, err)
	require.NotEmpty(t, allChunks, "CreateCourierEnvelopesFromPayloads returned empty chunks")
	t.Logf("Alice: Created %d chunks for both channels (packed efficiently)", len(allChunks))

	// Step 5: Write all copy stream chunks to the temporary channel
	t.Log("=== Step 5: Writing all chunks to temporary channel ===")
	tempIndex := tempFirstIndex
	replyIndex := uint8(0)

	for i, chunk := range allChunks {
		t.Logf("--- Writing chunk %d/%d to temporary channel ---", i+1, len(allChunks))

		// Encrypt the chunk for the copy stream
		ciphertext, envDesc, envHash, err := aliceThinClient.EncryptWrite(ctx, chunk, tempWriteCap, tempIndex)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext, "EncryptWrite returned empty ciphertext for chunk %d", i+1)
		t.Logf("Alice: Encrypted chunk %d (%d bytes plaintext -> %d bytes ciphertext)", i+1, len(chunk), len(ciphertext))

		// Send the encrypted chunk to the copy stream
		_, err = aliceThinClient.StartResendingEncryptedMessage(
			ctx, nil, tempWriteCap, nil, &replyIndex,
			envDesc, ciphertext, envHash)
		require.NoError(t, err)
		t.Logf("Alice: Sent chunk %d to temporary channel", i+1)

		// Increment temp index for next chunk
		tempIndex, err = aliceThinClient.NextMessageBoxIndex(ctx, tempIndex)
		require.NoError(t, err)
	}

	// Wait for chunks to propagate
	t.Log("Waiting for copy stream chunks to propagate (30 seconds)")
	time.Sleep(30 * time.Second)

	// Step 6: Send Copy command to courier using ARQ
	t.Log("=== Step 6: Sending Copy command to courier via ARQ ===")
	err = aliceThinClient.StartResendingCopyCommand(ctx, tempWriteCap)
	require.NoError(t, err)
	t.Log("Alice: Copy command completed successfully via ARQ")

	// Step 7: Bob reads from both channels and verifies payloads
	t.Log("=== Step 7: Bob reads from both channels ===")

	// Read from Channel 1
	t.Log("--- Bob reading from Channel 1 ---")
	bob1Ciphertext, bob1NextIndex, bob1EnvDesc, bob1EnvHash, err := bobThinClient.EncryptRead(ctx, chan1ReadCap, chan1FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 1")

	bob1Plaintext, err := bobThinClient.StartResendingEncryptedMessage(
		ctx, chan1ReadCap, nil, bob1NextIndex, &replyIndex,
		bob1EnvDesc, bob1Ciphertext, bob1EnvHash)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Plaintext, "Bob: Failed to receive data from Channel 1")
	t.Logf("Bob: Received from Channel 1: %q (%d bytes)", bob1Plaintext, len(bob1Plaintext))

	// Verify Channel 1 payload
	require.Equal(t, payload1, bob1Plaintext, "Channel 1 payload doesn't match")
	t.Log("✓ Channel 1 payload verified!")

	// Read from Channel 2
	t.Log("--- Bob reading from Channel 2 ---")
	bob2Ciphertext, bob2NextIndex, bob2EnvDesc, bob2EnvHash, err := bobThinClient.EncryptRead(ctx, chan2ReadCap, chan2FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 2")

	bob2Plaintext, err := bobThinClient.StartResendingEncryptedMessage(
		ctx, chan2ReadCap, nil, bob2NextIndex, &replyIndex,
		bob2EnvDesc, bob2Ciphertext, bob2EnvHash)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Plaintext, "Bob: Failed to receive data from Channel 2")
	t.Logf("Bob: Received from Channel 2: %q (%d bytes)", bob2Plaintext, len(bob2Plaintext))

	// Verify Channel 2 payload
	require.Equal(t, payload2, bob2Plaintext, "Channel 2 payload doesn't match")
	t.Log("✓ Channel 2 payload verified!")

	t.Log("\n✓ SUCCESS: Efficient multi-channel Copy Command test passed! Both payloads packed efficiently and delivered to correct channels!")
}

// TestNestedCopyCommands tests N-depth nested Copy Commands (matryoshka dolls):
//
// The flow for N nested copies:
//  1. Alice builds N layers from inside out:
//     - Layer 0 (innermost): CourierEnvelopes(payload) → DEST
//     - Layer 1: CourierEnvelopes(layer0_stream) → intermediate[0]
//     - Layer N-1 (outermost): CourierEnvelopes(layerN-2_stream) → intermediate[N-2]
//  2. Alice writes outermost layer to OUTER_TEMP channel
//  3. Alice issues N CopyCommands, each time:
//     - CopyCommand processes current layer
//     - Read result from intermediate channel
//     - Write to new exec temp channel (for next CopyCommand)
//  4. Bob reads DEST → gets plaintext!
//
// This demonstrates that N-depth nesting requires N CopyCommands.
func TestNestedCopyCommands(t *testing.T) {
	alice := setupThinClient(t)
	defer alice.Close()
	bob := setupThinClient(t)
	defer bob.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	// Get all available couriers and use them for nesting depth
	allCouriers, err := alice.GetAllCouriers()
	require.NoError(t, err)
	require.NotEmpty(t, allCouriers, "at least one courier must be available")

	// Use all available couriers (allows reuse if only 1 exists)
	depth := len(allCouriers)
	if depth > 3 {
		depth = 3 // Cap at 3 for reasonable test duration
	}
	couriers := allCouriers[:depth]
	t.Logf("Using %d couriers for %d-level nested copy", len(couriers), depth)

	// Create destination channel
	destSeed := make([]byte, 32)
	_, err = rand.Reader.Read(destSeed)
	require.NoError(t, err)
	destWriteCap, bobReadCap, destFirstIndex, err := alice.NewKeypair(ctx, destSeed)
	require.NoError(t, err)

	// Payload with length prefix
	secret := []byte("🎁 THE SECRET MESSAGE AT THE CENTER OF THE MATRYOSHKA! 🪆")
	payload := make([]byte, 4+len(secret))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(secret)))
	copy(payload[4:], secret)

	// Send nested copy through courier path
	err = alice.SendNestedCopy(ctx, payload, destWriteCap, destFirstIndex, couriers)
	require.NoError(t, err)
	t.Log("✓ SendNestedCopy completed")

	// Bob reads the payload
	var received []byte
	readIdx := destFirstIndex
	replyIndex := uint8(0)
	for {
		ciphertext, nextIdx, envDesc, envHash, err := bob.EncryptRead(ctx, bobReadCap, readIdx)
		require.NoError(t, err)
		chunk, err := bob.StartResendingEncryptedMessage(ctx, bobReadCap, nil, nextIdx, &replyIndex, envDesc, ciphertext, envHash)
		require.NoError(t, err)
		received = append(received, chunk...)
		if len(received) >= 4 && uint32(len(received)) >= binary.BigEndian.Uint32(received[:4])+4 {
			break
		}
		readIdx, _ = bob.NextMessageBoxIndex(ctx, readIdx)
	}

	require.Equal(t, payload, received)
	t.Logf("✓ Bob received: %s", string(received[4:]))
}

// TestTombstoning tests the tombstoning API:
// 1. Alice writes a message to a box
// 2. Bob reads and verifies the message
// 3. Alice tombstones the box (overwrites with zeros)
// 4. Bob reads again and verifies the tombstone
func TestTombstoning(t *testing.T) {
	alice := setupThinClient(t)
	defer alice.Close()
	bob := setupThinClient(t)
	defer bob.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	geo := alice.GetConfig().PigeonholeGeometry

	// Create keypair
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	writeCap, readCap, firstIndex, err := alice.NewKeypair(ctx, seed)
	require.NoError(t, err)
	t.Log("✓ Created keypair")

	// Step 1: Alice writes a message
	message := []byte("Secret message that will be tombstoned")
	ciphertext, envDesc, envHash, err := alice.EncryptWrite(ctx, message, writeCap, firstIndex)
	require.NoError(t, err)

	replyIndex := uint8(0)
	_, err = alice.StartResendingEncryptedMessage(ctx, nil, writeCap, nil, &replyIndex, envDesc, ciphertext, envHash)
	require.NoError(t, err)
	t.Log("✓ Alice wrote message")

	// Step 2: Bob reads and verifies
	ciphertext, nextIdx, envDesc, envHash, err := bob.EncryptRead(ctx, readCap, firstIndex)
	require.NoError(t, err)
	plaintext, err := bob.StartResendingEncryptedMessage(ctx, readCap, nil, nextIdx, &replyIndex, envDesc, ciphertext, envHash)
	require.NoError(t, err)
	require.Equal(t, message, plaintext)
	t.Logf("✓ Bob read message: %q", string(plaintext))

	// Step 3: Alice tombstones the box
	err = alice.TombstoneBox(ctx, geo, writeCap, firstIndex)
	require.NoError(t, err)
	t.Log("✓ Alice tombstoned the box")

	// Step 4: Bob reads again and verifies tombstone
	ciphertext, nextIdx, envDesc, envHash, err = bob.EncryptRead(ctx, readCap, firstIndex)
	require.NoError(t, err)
	plaintext, err = bob.StartResendingEncryptedMessage(ctx, readCap, nil, nextIdx, &replyIndex, envDesc, ciphertext, envHash)
	require.NoError(t, err)
	require.True(t, thin.IsTombstonePlaintext(geo, plaintext), "Expected tombstone plaintext (all zeros)")
	t.Log("✓ Bob verified tombstone")
}
