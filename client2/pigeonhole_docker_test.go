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
	aliceResult, err := aliceThinClient.StartResendingEncryptedMessage(
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
	require.Empty(t, aliceResult.Plaintext, "Alice: Write operation should return empty plaintext")
	t.Log("Alice: Started resending encrypted write message")

	// Wait for message propagation to storage replicas
	t.Log("Waiting for message propagation to storage replicas (30 seconds)")
	time.Sleep(30 * time.Second)

	// Step 4: Bob encrypts a read request using EncryptRead
	t.Log("=== Step 4: Bob encrypts a read request using EncryptRead ===")

	bobCiphertext, bobEnvDesc, bobEnvHash, err := bobThinClient.EncryptRead(ctx, bobReadCap, aliceFirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bobCiphertext, "Bob: EncryptRead returned empty ciphertext")
	t.Logf("Bob: Encrypted read request (%d bytes ciphertext)", len(bobCiphertext))
	aliceFirstIndexBytes, err := aliceFirstIndex.MarshalBinary()
	require.NoError(t, err)

	// Step 5: Bob sends the read request and receives Alice's encrypted message
	t.Log("=== Step 5: Bob sends read request and receives encrypted message ===")
	bobResult, err := bobThinClient.StartResendingEncryptedMessage(
		ctx,
		bobReadCap,          // readCap
		nil,                 // writeCap (nil for read operations)
		aliceFirstIndexBytes, // nextMessageIndex
		&replyIndex,         // replyIndex
		bobEnvDesc,          // envelopeDescriptor
		bobCiphertext,       // messageCiphertext
		bobEnvHash,          // envelopeHash
	)
	require.NoError(t, err)
	require.NotEmpty(t, bobResult.Plaintext, "Bob: Failed to receive decrypted message")
	t.Logf("Bob: Received and decrypted message: %q", bobResult.Plaintext)

	// Verify the decrypted message matches Alice's original message
	require.Equal(t, aliceMessage, bobResult.Plaintext, "Message mismatch: Bob's decrypted message doesn't match Alice's original")
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
		aliceResult, err := aliceThinClient.StartResendingEncryptedMessage(
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
		require.Empty(t, aliceResult.Plaintext, "Alice: Write operation should return empty plaintext")
		t.Logf("Alice: Started resending message %d", i+1)

		// Wait for message propagation
		t.Logf("Waiting for message %d propagation (10 seconds)", i+1)
		time.Sleep(10 * time.Second)

		// Bob encrypts read request
		t.Logf("Bob: Encrypting read request for message %d", i+1)

		bobCiphertext, bobEnvDesc, bobEnvHash, err := bobThinClient.EncryptRead(ctx, bobReadCap, bobCurrentIndex)
		require.NoError(t, err)
		require.NotEmpty(t, bobCiphertext, "Bob: EncryptRead returned empty ciphertext for message %d", i+1)
		t.Logf("Bob: Encrypted read request %d (%d bytes ciphertext)", i+1, len(bobCiphertext))
		bobCurrentIndexBytes, err := bobCurrentIndex.MarshalBinary()
		require.NoError(t, err)

		// Bob sends read request and receives Alice's encrypted message
		bobResult, err := bobThinClient.StartResendingEncryptedMessage(
			ctx,
			bobReadCap,          // readCap
			nil,                 // writeCap (nil for read operations)
			bobCurrentIndexBytes, // nextMessageIndex
			&replyIndex,         // replyIndex
			bobEnvDesc,          // envelopeDescriptor
			bobCiphertext,       // messageCiphertext
			bobEnvHash,    // envelopeHash
		)
		require.NoError(t, err)
		require.NotEmpty(t, bobResult.Plaintext, "Bob: Failed to receive message %d", i+1)
		t.Logf("Bob: Received and decrypted message %d: %q", i+1, bobResult.Plaintext)

		// Verify the decrypted message matches
		require.Equal(t, aliceMessage, bobResult.Plaintext, "Message %d mismatch", i+1)
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
		bobCiphertext, bobEnvDesc, bobEnvHash, err := bobThinClient.EncryptRead(ctx, bobReadCap, bobIndex)
		require.NoError(t, err)
		require.NotEmpty(t, bobCiphertext, "Bob: EncryptRead returned empty ciphertext")
		t.Logf("Bob: Encrypted read request %d", chunkNum)
		bobIndexBytes, err := bobIndex.MarshalBinary()
		require.NoError(t, err)

		// Bob sends read request and receives chunk
		bobResult, err := bobThinClient.StartResendingEncryptedMessage(
			ctx, bobReadCap, nil, bobIndexBytes, &replyIndex,
			bobEnvDesc, bobCiphertext, bobEnvHash)
		require.NoError(t, err)
		require.NotEmpty(t, bobResult.Plaintext, "Bob: Failed to receive chunk %d", chunkNum)
		t.Logf("Bob: Received and decrypted chunk %d (%d bytes)", chunkNum, len(bobResult.Plaintext))

		// Append chunk to reconstructed payload
		reconstructedPayload = append(reconstructedPayload, bobResult.Plaintext...)

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
	bob1Ciphertext, bob1EnvDesc, bob1EnvHash, err := bobThinClient.EncryptRead(ctx, chan1ReadCap, chan1FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 1")
	chan1FirstIndexBytes, err := chan1FirstIndex.MarshalBinary()
	require.NoError(t, err)

	bob1Result, err := bobThinClient.StartResendingEncryptedMessage(
		ctx, chan1ReadCap, nil, chan1FirstIndexBytes, &replyIndex,
		bob1EnvDesc, bob1Ciphertext, bob1EnvHash)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Result.Plaintext, "Bob: Failed to receive data from Channel 1")
	t.Logf("Bob: Received from Channel 1: %q (%d bytes)", bob1Result.Plaintext, len(bob1Result.Plaintext))

	// Verify Channel 1 payload
	require.Equal(t, payload1, bob1Result.Plaintext, "Channel 1 payload doesn't match")
	t.Log("✓ Channel 1 payload verified!")

	// Read from Channel 2
	t.Log("--- Bob reading from Channel 2 ---")
	bob2Ciphertext, bob2EnvDesc, bob2EnvHash, err := bobThinClient.EncryptRead(ctx, chan2ReadCap, chan2FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 2")
	chan2FirstIndexBytes, err := chan2FirstIndex.MarshalBinary()
	require.NoError(t, err)

	bob2Result, err := bobThinClient.StartResendingEncryptedMessage(
		ctx, chan2ReadCap, nil, chan2FirstIndexBytes, &replyIndex,
		bob2EnvDesc, bob2Ciphertext, bob2EnvHash)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Result.Plaintext, "Bob: Failed to receive data from Channel 2")
	t.Logf("Bob: Received from Channel 2: %q (%d bytes)", bob2Result.Plaintext, len(bob2Result.Plaintext))

	// Verify Channel 2 payload
	require.Equal(t, payload2, bob2Result.Plaintext, "Channel 2 payload doesn't match")
	t.Log("✓ Channel 2 payload verified!")

	t.Log("\n✓ SUCCESS: Multi-channel Copy Command test passed! Payload1 written to Channel 1 and Payload2 written to Channel 2 atomically!")
}

// TestCopyCommandMultiChannelEfficient tests the space-efficient multi-channel copy command
// using CreateCourierEnvelopesFromMultiPayload which packs envelopes from different destinations
// together without wasting space in the copy stream.
//
// This test verifies:
// - The CreateCourierEnvelopesFromMultiPayload API works correctly
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

	// Step 4: Create copy stream chunks using CreateCourierEnvelopesFromMultiPayload (efficient API)
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
	allChunksResult, err := aliceThinClient.CreateCourierEnvelopesFromMultiPayload(ctx, streamID, destinations, true)
	require.NoError(t, err)
	require.NotEmpty(t, allChunksResult.Envelopes, "CreateCourierEnvelopesFromMultiPayload returned empty chunks")
	t.Logf("Alice: Created %d chunks for both channels (packed efficiently)", len(allChunksResult.Envelopes))

	// Step 5: Write all copy stream chunks to the temporary channel
	t.Log("=== Step 5: Writing all chunks to temporary channel ===")
	tempIndex := tempFirstIndex
	replyIndex := uint8(0)

	for i, chunk := range allChunksResult.Envelopes {
		t.Logf("--- Writing chunk %d/%d to temporary channel ---", i+1, len(allChunksResult.Envelopes))

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
	bob1Ciphertext, bob1EnvDesc, bob1EnvHash, err := bobThinClient.EncryptRead(ctx, chan1ReadCap, chan1FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 1")
	chan1FirstIndexBytes, err := chan1FirstIndex.MarshalBinary()
	require.NoError(t, err)

	bob1Result, err := bobThinClient.StartResendingEncryptedMessage(
		ctx, chan1ReadCap, nil, chan1FirstIndexBytes, &replyIndex,
		bob1EnvDesc, bob1Ciphertext, bob1EnvHash)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Result.Plaintext, "Bob: Failed to receive data from Channel 1")
	t.Logf("Bob: Received from Channel 1: %q (%d bytes)", bob1Result.Plaintext, len(bob1Result.Plaintext))

	// Verify Channel 1 payload
	require.Equal(t, payload1, bob1Result.Plaintext, "Channel 1 payload doesn't match")
	t.Log("✓ Channel 1 payload verified!")

	// Read from Channel 2
	t.Log("--- Bob reading from Channel 2 ---")
	bob2Ciphertext, bob2EnvDesc, bob2EnvHash, err := bobThinClient.EncryptRead(ctx, chan2ReadCap, chan2FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 2")
	chan2FirstIndexBytes, err := chan2FirstIndex.MarshalBinary()
	require.NoError(t, err)

	bob2Result, err := bobThinClient.StartResendingEncryptedMessage(
		ctx, chan2ReadCap, nil, chan2FirstIndexBytes, &replyIndex,
		bob2EnvDesc, bob2Ciphertext, bob2EnvHash)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Result.Plaintext, "Bob: Failed to receive data from Channel 2")
	t.Logf("Bob: Received from Channel 2: %q (%d bytes)", bob2Result.Plaintext, len(bob2Result.Plaintext))

	// Verify Channel 2 payload
	require.Equal(t, payload2, bob2Result.Plaintext, "Channel 2 payload doesn't match")
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
		ciphertext, envDesc, envHash, err := bob.EncryptRead(ctx, bobReadCap, readIdx)
		require.NoError(t, err)
		readIdxBytes, err := readIdx.MarshalBinary()
		require.NoError(t, err)
		chunkResult, err := bob.StartResendingEncryptedMessage(ctx, bobReadCap, nil, readIdxBytes, &replyIndex, envDesc, ciphertext, envHash)
		require.NoError(t, err)
		received = append(received, chunkResult.Plaintext...)
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
// 3. Alice tombstones the box (deletes it with an empty payload)
// 4. Bob reads again and verifies the tombstone
func TestTombstoning(t *testing.T) {
	alice := setupThinClient(t)
	defer alice.Close()
	bob := setupThinClient(t)
	defer bob.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

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

	t.Log("Waiting for 30 seconds for message propagation...")
	time.Sleep(30 * time.Second)

	// Step 2: Bob reads and verifies
	ciphertext, envDesc, envHash, err := bob.EncryptRead(ctx, readCap, firstIndex)
	require.NoError(t, err)
	firstIndexBytes, err := firstIndex.MarshalBinary()
	require.NoError(t, err)
	readResult, err := bob.StartResendingEncryptedMessage(ctx, readCap, nil, firstIndexBytes, &replyIndex, envDesc, ciphertext, envHash)
	require.NoError(t, err)
	require.Equal(t, message, readResult.Plaintext)
	t.Logf("✓ Bob read message: %q", string(readResult.Plaintext))

	// Step 3: Alice tombstones the box
	tombCiphertext, tombEnvDesc, tombEnvHash, err := alice.TombstoneBox(ctx, writeCap, firstIndex)
	require.NoError(t, err)
	_, err = alice.StartResendingEncryptedMessage(ctx, nil, writeCap, nil, nil, tombEnvDesc, tombCiphertext, tombEnvHash)
	require.NoError(t, err)
	t.Log("✓ Alice tombstoned the box")

	// Step 4: Bob polls for tombstone with retries
	const maxAttempts = 6
	const pollInterval = 10 * time.Second
	var tombstoneVerified bool

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		t.Logf("Polling for tombstone (attempt %d/%d)...", attempt, maxAttempts)
		time.Sleep(pollInterval)

		ciphertext, envDesc, envHash, err = bob.EncryptRead(ctx, readCap, firstIndex)
		require.NoError(t, err)
		tombResult, err := bob.StartResendingEncryptedMessage(ctx, readCap, nil, firstIndexBytes, &replyIndex, envDesc, ciphertext, envHash)
		require.NoError(t, err)

		if len(tombResult.Plaintext) == 0 {
			tombstoneVerified = true
			t.Logf("✓ Bob verified tombstone on attempt %d", attempt)
			break
		}
		t.Logf("  Still seeing original message, retrying...")
	}

	require.True(t, tombstoneVerified, "Tombstone not propagated after %d attempts", maxAttempts)
}

// TestTombstoneRange tests the TombstoneRange API:
// 1. Alice writes multiple messages to consecutive boxes
// 2. Bob reads and verifies each message
// 3. Alice tombstones all boxes using TombstoneRange
// 4. Bob reads again and verifies all boxes are tombstoned
func TestTombstoneRange(t *testing.T) {
	alice := setupThinClient(t)
	defer alice.Close()
	bob := setupThinClient(t)
	defer bob.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Create keypair
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	writeCap, readCap, firstIndex, err := alice.NewKeypair(ctx, seed)
	require.NoError(t, err)
	t.Log("✓ Created keypair")

	// Write 3 messages to consecutive boxes
	const numMessages = 3
	messages := [][]byte{
		[]byte("Message 1 - will be tombstoned"),
		[]byte("Message 2 - will be tombstoned"),
		[]byte("Message 3 - will be tombstoned"),
	}

	writeIdx := firstIndex
	replyIndex := uint8(0)
	for i, msg := range messages {
		ciphertext, envDesc, envHash, err := alice.EncryptWrite(ctx, msg, writeCap, writeIdx)
		require.NoError(t, err)
		_, err = alice.StartResendingEncryptedMessage(ctx, nil, writeCap, nil, &replyIndex, envDesc, ciphertext, envHash)
		require.NoError(t, err)
		t.Logf("✓ Alice wrote message %d", i+1)

		writeIdx, err = alice.NextMessageBoxIndex(ctx, writeIdx)
		require.NoError(t, err)
	}

	t.Log("Waiting for 30 seconds for message propagation...")
	time.Sleep(30 * time.Second)

	// Bob reads and verifies all messages
	readIdx := firstIndex
	for i, expectedMsg := range messages {
		ciphertext, envDesc, envHash, err := bob.EncryptRead(ctx, readCap, readIdx)
		require.NoError(t, err)
		readIdxBytes, err := readIdx.MarshalBinary()
		require.NoError(t, err)
		readResult, err := bob.StartResendingEncryptedMessage(ctx, readCap, nil, readIdxBytes, &replyIndex, envDesc, ciphertext, envHash)
		require.NoError(t, err)
		require.Equal(t, expectedMsg, readResult.Plaintext)
		t.Logf("✓ Bob read message %d: %q", i+1, string(readResult.Plaintext))

		readIdx, err = bob.NextMessageBoxIndex(ctx, readIdx)
		require.NoError(t, err)
	}

	// Alice tombstones all boxes using TombstoneRange
	result, err := alice.TombstoneRange(ctx, writeCap, firstIndex, numMessages)
	require.NoError(t, err)
	require.Len(t, result.Envelopes, numMessages)
	t.Logf("✓ TombstoneRange created %d envelopes", len(result.Envelopes))

	// Send all tombstone envelopes
	for i, envelope := range result.Envelopes {
		_, err = alice.StartResendingEncryptedMessage(
			ctx, nil, writeCap, nil, nil,
			envelope.EnvelopeDescriptor, envelope.MessageCiphertext, envelope.EnvelopeHash,
		)
		require.NoError(t, err)
		t.Logf("✓ Sent tombstone envelope %d", i+1)
	}

	t.Log("Waiting for 60 seconds for tombstone propagation...")
	time.Sleep(60 * time.Second)

	// Bob reads again and verifies all boxes are tombstoned
	readIdx = firstIndex
	for i := 0; i < numMessages; i++ {
		ciphertext, envDesc, envHash, err := bob.EncryptRead(ctx, readCap, readIdx)
		require.NoError(t, err)
		readIdxBytes, err := readIdx.MarshalBinary()
		require.NoError(t, err)
		tombResult, err := bob.StartResendingEncryptedMessage(ctx, readCap, nil, readIdxBytes, &replyIndex, envDesc, ciphertext, envHash)
		require.NoError(t, err)
		require.True(t, len(tombResult.Plaintext) == 0, "Expected tombstone plaintext (empty) for box %d", i+1)
		t.Logf("✓ Bob verified tombstone %d", i+1)

		readIdx, err = bob.NextMessageBoxIndex(ctx, readIdx)
		require.NoError(t, err)
	}

	t.Logf("✓ All %d boxes successfully tombstoned and verified", numMessages)
}

// TestBoxIDNotFoundError tests that we receive an ErrBoxIDNotFound error
// when attempting to read from a box that has never been written to.
//
// This test verifies:
// - Reading from a non-existent box returns ErrBoxIDNotFound
// - The error can be checked using errors.Is()
func TestBoxIDNotFoundError(t *testing.T) {
	// Setup Bob thin client (reader)
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	// Validate PKI document
	validatePKIDocument(t, bobThinClient)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create a new keypair - but we will NOT write any message to it
	t.Log("=== Creating a fresh keypair (no message will be written) ===")
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	_, readCap, firstIndex, err := bobThinClient.NewKeypair(ctx, seed)
	require.NoError(t, err)
	require.NotNil(t, readCap, "ReadCap should not be nil")
	t.Log("Created fresh keypair - no message written to this box")

	// Attempt to read from the non-existent box
	t.Log("=== Attempting to read from non-existent box ===")
	bobCiphertext, bobEnvDesc, bobEnvHash, err := bobThinClient.EncryptRead(ctx, readCap, firstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bobCiphertext, "EncryptRead should return ciphertext")
	t.Log("Encrypted read request for non-existent box")
	firstIndexBytes, err := firstIndex.MarshalBinary()
	require.NoError(t, err)

	// Send the read request - this should fail with ErrBoxIDNotFound
	// Use StartResendingEncryptedMessageNoRetry to get immediate error without retries
	replyIndex := uint8(0)
	_, err = bobThinClient.StartResendingEncryptedMessageNoRetry(
		ctx,
		readCap,          // readCap
		nil,              // writeCap (nil for read operations)
		firstIndexBytes,  // nextMessageIndex
		&replyIndex,      // replyIndex
		bobEnvDesc,       // envelopeDescriptor
		bobCiphertext,    // messageCiphertext
		bobEnvHash,       // envelopeHash
	)

	// Verify we got the expected ErrBoxIDNotFound error
	require.Error(t, err, "Expected an error when reading from non-existent box")
	require.ErrorIs(t, err, thin.ErrBoxIDNotFound, "Expected ErrBoxIDNotFound error, got: %v", err)

	t.Log("✓ SUCCESS: Correctly received ErrBoxIDNotFound error when reading from non-existent box")
}

// TestReadBeforeWrite tests the race condition where a read is attempted
// before the corresponding write has been made. This verifies that the
// retry logic in kpclientd (for BoxIDNotFound errors) works correctly:
//
// 1. Alice and Bob share a keypair (same box ID)
// 2. Bob starts reading BEFORE Alice writes (box doesn't exist yet)
// 3. Alice writes to the box after a delay
// 4. Bob's read should eventually succeed due to retry mechanism
//
// This test validates that the default retry behavior (NoRetryOnBoxIDNotFound=false)
// correctly handles the case where data hasn't been replicated yet.
func TestReadBeforeWrite(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Create keypair - Alice gets WriteCap, Bob gets ReadCap, both target same box
	t.Log("=== Setup: Creating shared keypair ===")
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	aliceWriteCap, bobReadCap, firstIndex, err := aliceThinClient.NewKeypair(ctx, seed)
	require.NoError(t, err)
	require.NotNil(t, aliceWriteCap, "Alice: WriteCap is nil")
	require.NotNil(t, bobReadCap, "Bob: ReadCap is nil")

	// Log the box ID both will be using
	boxID := firstIndex.BoxIDForContext(bobReadCap, constants.PIGEONHOLE_CTX)
	t.Logf("Shared Box ID: %x", boxID.Bytes())

	// Channel to receive Bob's read result
	type readResult struct {
		plaintext []byte
		err       error
	}
	bobResultChan := make(chan readResult, 1)

	// Start Bob's read in a goroutine BEFORE Alice writes
	// This read will initially fail with BoxIDNotFound, but should retry
	t.Log("=== Step 1: Bob starts reading (box doesn't exist yet) ===")
	go func() {
		// Encrypt Bob's read request
		bobCiphertext, bobEnvDesc, bobEnvHash, err := bobThinClient.EncryptRead(ctx, bobReadCap, firstIndex)
		if err != nil {
			bobResultChan <- readResult{nil, err}
			return
		}
		firstIndexBytes, err := firstIndex.MarshalBinary()
		if err != nil {
			bobResultChan <- readResult{nil, err}
			return
		}

		// Send read request - this uses DEFAULT behavior (retries enabled)
		// The read will fail initially with BoxIDNotFound, but kpclientd will retry
		replyIndex := uint8(0)
		result, err := bobThinClient.StartResendingEncryptedMessage(
			ctx,
			bobReadCap,       // readCap
			nil,              // writeCap (nil for read operations)
			firstIndexBytes,  // nextMessageIndex
			&replyIndex,      // replyIndex
			bobEnvDesc,       // envelopeDescriptor
			bobCiphertext,    // messageCiphertext
			bobEnvHash,       // envelopeHash
		)
		var pt []byte
		if result != nil {
			pt = result.Plaintext
		}
		bobResultChan <- readResult{pt, err}
	}()

	// Wait a bit to ensure Bob's read is in-flight and retrying
	t.Log("=== Step 2: Waiting 5 seconds before Alice writes ===")
	time.Sleep(5 * time.Second)

	// Alice writes the message
	t.Log("=== Step 3: Alice writes message (while Bob is retrying) ===")
	aliceMessage := []byte("Hello Bob! I wrote this after you started reading.")
	t.Logf("Alice: Writing message (%d bytes): %q", len(aliceMessage), aliceMessage)

	aliceCiphertext, aliceEnvDesc, aliceEnvHash, err := aliceThinClient.EncryptWrite(ctx, aliceMessage, aliceWriteCap, firstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, aliceCiphertext, "Alice: EncryptWrite returned empty ciphertext")

	replyIndex := uint8(0)
	_, err = aliceThinClient.StartResendingEncryptedMessage(
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
	t.Log("Alice: Write completed")

	// Wait for Bob's read to complete
	t.Log("=== Step 4: Waiting for Bob's read to succeed ===")
	select {
	case result := <-bobResultChan:
		require.NoError(t, result.err, "Bob's read should eventually succeed after Alice's write")
		require.NotEmpty(t, result.plaintext, "Bob should receive the message")
		require.Equal(t, aliceMessage, result.plaintext, "Bob's decrypted message should match Alice's original")
		t.Logf("Bob: Received message: %q", result.plaintext)
		t.Log("✓ SUCCESS: Bob's read succeeded after Alice's write (retry mechanism worked!)")

	case <-ctx.Done():
		t.Fatal("Test timed out waiting for Bob's read to complete")
	}
}

// TestBoxAlreadyExistsError tests that we receive an ErrBoxAlreadyExists error
// when attempting to write to a box that has already been written to.
//
// This test verifies:
// - Writing to a box succeeds the first time
// - Writing to the same box again returns ErrBoxAlreadyExists
// - The error can be checked using errors.Is()
func TestBoxAlreadyExistsError(t *testing.T) {
	// Setup thin client
	thinClient := setupThinClient(t)
	defer thinClient.Close()

	// Validate PKI document
	validatePKIDocument(t, thinClient)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create a new keypair
	t.Log("=== Creating a keypair for the test ===")
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	writeCap, _, firstIndex, err := thinClient.NewKeypair(ctx, seed)
	require.NoError(t, err)
	require.NotNil(t, writeCap, "WriteCap should not be nil")
	t.Log("✓ Created keypair")

	// First write - should succeed
	t.Log("=== First write (should succeed) ===")
	message1 := []byte("First message - this should work")
	ciphertext1, envDesc1, envHash1, err := thinClient.EncryptWrite(ctx, message1, writeCap, firstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext1, "EncryptWrite should return ciphertext")
	t.Log("✓ Encrypted first message")

	// Send the first write
	_, err = thinClient.StartResendingEncryptedMessage(
		ctx,
		nil,         // readCap (nil for write operations)
		writeCap,    // writeCap
		nil,         // nextMessageIndex (nil for write operations)
		nil,         // replyIndex (nil for write operations)
		envDesc1,    // envelopeDescriptor
		ciphertext1, // messageCiphertext
		envHash1,    // envelopeHash
	)
	require.NoError(t, err, "First write should succeed")
	t.Log("✓ First write succeeded")

	// Wait for propagation to ensure the first write is fully replicated
	t.Log("Waiting for message propagation...")
	time.Sleep(5 * time.Second)

	// Second write to the SAME box - should fail with ErrBoxAlreadyExists
	t.Log("=== Second write to same box (should fail) ===")
	message2 := []byte("Second message - this should fail")
	ciphertext2, envDesc2, envHash2, err := thinClient.EncryptWrite(ctx, message2, writeCap, firstIndex)
	require.NoError(t, err, "EncryptWrite should succeed even for duplicate")
	t.Log("✓ Encrypted second message")

	// Send the second write - should fail with BoxAlreadyExists
	// Use StartResendingEncryptedMessageReturnBoxExists to get the error instead of
	// treating it as idempotent success
	_, err = thinClient.StartResendingEncryptedMessageReturnBoxExists(
		ctx,
		nil,         // readCap
		writeCap,    // writeCap
		nil,         // nextMessageIndex
		nil,         // replyIndex
		envDesc2,    // envelopeDescriptor
		ciphertext2, // messageCiphertext
		envHash2,    // envelopeHash
	)

	// Verify we got the expected ErrBoxAlreadyExists error
	require.Error(t, err, "Expected an error when writing to existing box")
	require.ErrorIs(t, err, thin.ErrBoxAlreadyExists, "Expected ErrBoxAlreadyExists error, got: %v", err)

	t.Log("✓ SUCCESS: Correctly received ErrBoxAlreadyExists error when writing to existing box")
}

func TestCopyOntoAlreadyExistingBoxError(t *testing.T) {
	// Setup thin client
	thinClient := setupThinClient(t)
	defer thinClient.Close()

	// Validate PKI document
	validatePKIDocument(t, thinClient)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create a new keypair
	t.Log("=== Creating a keypair for the test ===")
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	writeCap, _, firstIndex, err := thinClient.NewKeypair(ctx, seed)
	require.NoError(t, err)
	require.NotNil(t, writeCap, "WriteCap should not be nil")
	t.Log("✓ Created keypair")

	// First write - should succeed
	t.Log("=== First write (should succeed) ===")
	message1 := []byte("First message - this should work")
	ciphertext1, envDesc1, envHash1, err := thinClient.EncryptWrite(ctx, message1, writeCap, firstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext1, "EncryptWrite should return ciphertext")
	t.Log("✓ Encrypted first message")

	// Send the first write
	_, err = thinClient.StartResendingEncryptedMessage(
		ctx,
		nil,         // readCap (nil for write operations)
		writeCap,    // writeCap
		nil,         // nextMessageIndex (nil for write operations)
		nil,         // replyIndex (nil for write operations)
		envDesc1,    // envelopeDescriptor
		ciphertext1, // messageCiphertext
		envHash1,    // envelopeHash
	)
	require.NoError(t, err, "First write should succeed")
	t.Log("✓ First write succeeded")

	// Wait for propagation to ensure the first write is fully replicated
	t.Log("Waiting for message propagation...")
	time.Sleep(5 * time.Second)

	// Compose copy temp stream
	tempSeed := make([]byte, 32)
	_, err = rand.Reader.Read(tempSeed)
	require.NoError(t, err)

	tempWriteCap, _, tempFirstIndex, err := thinClient.NewKeypair(ctx, tempSeed)
	require.NoError(t, err)
	require.NotNil(t, tempWriteCap, "Temp WriteCap is nil")

	largePayload := make([]byte, 2000)
	_, err = rand.Reader.Read(largePayload)
	require.NoError(t, err)

	streamID := thinClient.NewStreamID()
	copyStreamChunks, err := thinClient.CreateCourierEnvelopesFromPayload(ctx, streamID, largePayload, writeCap, firstIndex, true /* isLast */)
	require.NoError(t, err)
	require.NotEmpty(t, copyStreamChunks, "CreateCourierEnvelopesFromPayload returned empty chunks")
	numChunks := len(copyStreamChunks)

	tempIndex := tempFirstIndex
	replyIndex := uint8(0)

	for i, chunk := range copyStreamChunks {
		t.Logf("--- Writing copy stream chunk %d/%d to temporary channel ---", i+1, numChunks)

		// Encrypt the chunk for the copy stream
		ciphertext, envDesc, envHash, err := thinClient.EncryptWrite(ctx, chunk, tempWriteCap, tempIndex)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext, "EncryptWrite returned empty ciphertext for chunk %d", i+1)
		t.Logf("Alice: Encrypted copy stream chunk %d (%d bytes plaintext -> %d bytes ciphertext)", i+1, len(chunk), len(ciphertext))

		// Send the encrypted chunk to the copy stream
		_, err = thinClient.StartResendingEncryptedMessage(
			ctx, nil, tempWriteCap, nil, &replyIndex,
			envDesc, ciphertext, envHash)
		require.NoError(t, err)
		t.Logf("Alice: Sent copy stream chunk %d to temporary channel", i+1)

		// Increment temp index for next chunk
		tempIndex, err = thinClient.NextMessageBoxIndex(ctx, tempIndex)
		require.NoError(t, err)
	}

	// Wait for all chunks to propagate to the copy stream
	t.Log("Waiting for copy stream chunks to propagate to temporary channel (30 seconds)")
	time.Sleep(30 * time.Second)

	err = thinClient.StartResendingCopyCommand(ctx, tempWriteCap)
	require.Error(t, err)
}
