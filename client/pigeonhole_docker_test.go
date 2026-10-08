//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/client/thin"
)

func skipInShortMode(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("slow docker integration test; runs in the full (release, schedule, or interop) suite")
	}
}

// TestNewPigeonholeAPIAliceSendsBob tests the complete end-to-end flow of the new Pigeonhole API:
// 1. Alice creates a WriteCap and derives a ReadCap for Bob
// 2. Alice encrypts a message using EncryptWrite
// 3. Alice sends the encrypted message via StartResendingEncryptedMessage
// 4. Bob encrypts a read request using EncryptRead
// 5. Bob sends the read request and receives Alice's encrypted message
// 6. Bob decrypts Alice's message
//
// This test uses:
// - Real client daemon (via thin client)
// - Real courier server (running in Docker)
// - Real replica servers (running in Docker)
// - Real mixnet (running in Docker)
// - Real PKI (running in Docker)
// - Real Sphinx packets
// - Real PQ Noise wire protocol
func TestNewPigeonholeAPIAliceSendsBob(t *testing.T) {
	t.Parallel()
	// Setup Alice and Bob thin clients
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	requireSharedPKIDocument(t, aliceThinClient, bobThinClient)

	// Step 1: Alice creates WriteCap and derives ReadCap for Bob using NewKeypair
	aliceSeed := make([]byte, 32)
	_, err := rand.Reader.Read(aliceSeed)
	require.NoError(t, err)

	aliceWriteCap, bobReadCap, aliceFirstIndex, err := aliceThinClient.NewKeypair(aliceSeed)
	require.NoError(t, err)
	require.NotNil(t, aliceWriteCap, "Alice: WriteCap is nil")
	require.NotNil(t, bobReadCap, "Alice: ReadCap is nil")

	// Verify that Alice's write box ID matches Bob's read box ID
	aliceBoxID, err := aliceFirstIndex.BoxIDForContext(aliceWriteCap.ReadCap(), constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	bobBoxID, err := aliceFirstIndex.BoxIDForContext(bobReadCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	require.Equal(t, aliceBoxID.Bytes(), bobBoxID.Bytes(), "Box IDs must match: Alice's write box ID != Bob's read box ID")
	t.Logf("Alice and Bob box ID: %x", aliceBoxID.Bytes())

	// Step 2: Alice encrypts a message using EncryptWrite
	// Make message bigger than 29 bytes to ensure courier returns ReplyTypePayload
	// (courier uses >29 byte threshold to distinguish between ACK and Payload replies)
	aliceMessage := []byte("Bob, the eagle has landed. Rendezvous at dawn. Bring the package and await further instructions.")

	aliceCiphertext, aliceEnvDesc, aliceEnvHash, _, err := aliceThinClient.EncryptWrite(aliceMessage, aliceWriteCap, aliceFirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, aliceCiphertext, "Alice: EncryptWrite returned empty ciphertext")

	// Step 3: Alice sends the encrypted message via StartResendingEncryptedMessage
	replyIndex := uint8(0)
	aliceResult, err := startResending(aliceThinClient,
		nil,             // readCap (nil for write operations)
		aliceWriteCap,   // writeCap
		nil,             // messageBoxIndex (not needed for writes)
		&replyIndex,     // replyIndex
		aliceEnvDesc,    // envelopeDescriptor
		aliceCiphertext, // messageCiphertext
		aliceEnvHash,    // envelopeHash
	)
	require.NoError(t, err)
	require.Empty(t, aliceResult.Plaintext, "Alice: Write operation should return empty plaintext")

	// Wait for message propagation to storage replicas
	time.Sleep(30 * time.Second)

	// Step 4: Bob encrypts a read request using EncryptRead

	bobCiphertext, bobEnvDesc, bobEnvHash, _, err := bobThinClient.EncryptRead(bobReadCap, aliceFirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bobCiphertext, "Bob: EncryptRead returned empty ciphertext")
	aliceFirstIndexBytes, err := aliceFirstIndex.MarshalBinary()
	require.NoError(t, err)

	// Step 5: Bob sends the read request and receives Alice's encrypted message
	bobResult, err := startResending(bobThinClient,
		bobReadCap,           // readCap
		nil,                  // writeCap (nil for read operations)
		aliceFirstIndexBytes, // messageBoxIndex
		&replyIndex,          // replyIndex
		bobEnvDesc,           // envelopeDescriptor
		bobCiphertext,        // messageCiphertext
		bobEnvHash,           // envelopeHash
	)
	require.NoError(t, err)
	require.NotEmpty(t, bobResult.Plaintext, "Bob: Failed to receive decrypted message")

	// Verify the decrypted message matches Alice's original message
	require.Equal(t, aliceMessage, bobResult.Plaintext, "Message mismatch: Bob's decrypted message doesn't match Alice's original")
}

// TestNewPigeonholeAPIMultipleMessages tests sending multiple sequential messages
// to verify that state management (PrepareNext/AdvanceState) works correctly
// in the real Docker environment.
func TestNewPigeonholeAPIMultipleMessages(t *testing.T) {
	skipInShortMode(t)
	t.Parallel()
	// Setup Alice and Bob thin clients
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	requireSharedPKIDocument(t, aliceThinClient, bobThinClient)

	// Step 1: Alice creates WriteCap and derives ReadCap for Bob using NewKeypair
	aliceSeed := make([]byte, 32)
	_, err := rand.Reader.Read(aliceSeed)
	require.NoError(t, err)

	aliceWriteCap, bobReadCap, aliceFirstIndex, err := aliceThinClient.NewKeypair(aliceSeed)
	require.NoError(t, err)
	require.NotNil(t, aliceWriteCap, "Alice: WriteCap is nil")
	require.NotNil(t, bobReadCap, "Alice: ReadCap is nil")

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
		aliceMessage := []byte(messages[i])

		// Alice encrypts and sends message

		aliceCiphertext, aliceEnvDesc, aliceEnvHash, aliceNextIndex, err := aliceThinClient.EncryptWrite(aliceMessage, aliceWriteCap, aliceCurrentIndex)
		require.NoError(t, err)
		require.NotEmpty(t, aliceCiphertext, "Alice: EncryptWrite returned empty ciphertext for message %d", i+1)
		require.NotNil(t, aliceNextIndex, "Alice: EncryptWrite returned nil next index for message %d", i+1)

		// Alice sends the encrypted message via StartResendingEncryptedMessage
		aliceResult, err := startResending(aliceThinClient,
			nil,             // readCap (nil for write operations)
			aliceWriteCap,   // writeCap
			nil,             // messageBoxIndex (not needed for writes)
			&replyIndex,     // replyIndex
			aliceEnvDesc,    // envelopeDescriptor
			aliceCiphertext, // messageCiphertext
			aliceEnvHash,    // envelopeHash
		)
		require.NoError(t, err)
		require.Empty(t, aliceResult.Plaintext, "Alice: Write operation should return empty plaintext")

		// Wait for message propagation
		time.Sleep(10 * time.Second)

		// Bob encrypts read request

		bobCiphertext, bobEnvDesc, bobEnvHash, bobNextIndex, err := bobThinClient.EncryptRead(bobReadCap, bobCurrentIndex)
		require.NoError(t, err)
		require.NotEmpty(t, bobCiphertext, "Bob: EncryptRead returned empty ciphertext for message %d", i+1)
		require.NotNil(t, bobNextIndex, "Bob: EncryptRead returned nil next index for message %d", i+1)
		bobCurrentIndexBytes, err := bobCurrentIndex.MarshalBinary()
		require.NoError(t, err)

		// Bob sends read request and receives Alice's encrypted message
		bobResult, err := startResending(bobThinClient,
			bobReadCap,           // readCap
			nil,                  // writeCap (nil for read operations)
			bobCurrentIndexBytes, // messageBoxIndex
			&replyIndex,          // replyIndex
			bobEnvDesc,           // envelopeDescriptor
			bobCiphertext,        // messageCiphertext
			bobEnvHash,           // envelopeHash
		)
		require.NoError(t, err)
		require.NotEmpty(t, bobResult.Plaintext, "Bob: Failed to receive message %d", i+1)

		// Verify the decrypted message matches
		require.Equal(t, aliceMessage, bobResult.Plaintext, "Message %d mismatch", i+1)

		// Advance state for next message using returned next index
		aliceCurrentIndex = aliceNextIndex
		bobCurrentIndex = bobNextIndex
	}

}

// TestNewPigeonholeAPIMultipleMessagesBulk tests sending multiple messages in bulk:
// all writes first, then all reads. Unlike TestNewPigeonholeAPIMultipleMessages which
// interleaves send/read per message, this test sends all 3 messages before reading any.
// This exercises multiple concurrent ARQ retry operations on the daemon — the pattern
// that was broken when arqResendCh had a buffer of 2 and silently dropped resends.
func TestNewPigeonholeAPIMultipleMessagesBulk(t *testing.T) {
	skipInShortMode(t)
	t.Parallel()
	// Setup Alice and Bob thin clients
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	requireSharedPKIDocument(t, aliceThinClient, bobThinClient)

	// Alice creates WriteCap and derives ReadCap for Bob
	aliceSeed := make([]byte, 32)
	_, err := rand.Reader.Read(aliceSeed)
	require.NoError(t, err)

	aliceWriteCap, bobReadCap, aliceFirstIndex, err := aliceThinClient.NewKeypair(aliceSeed)
	require.NoError(t, err)
	require.NotNil(t, aliceWriteCap)
	require.NotNil(t, bobReadCap)

	numMessages := 3
	messages := []string{
		"Message 1: The package has been delivered.",
		"Message 2: Proceed to the safe house.",
		"Message 3: Mission accomplished.",
	}

	// Alice sends ALL messages first
	aliceCurrentIndex := aliceFirstIndex
	replyIndex := uint8(0)

	for i := 0; i < numMessages; i++ {
		aliceMessage := []byte(messages[i])

		aliceCiphertext, aliceEnvDesc, aliceEnvHash, aliceNextIndex, err := aliceThinClient.EncryptWrite(aliceMessage, aliceWriteCap, aliceCurrentIndex)
		require.NoError(t, err)
		require.NotEmpty(t, aliceCiphertext)
		require.NotNil(t, aliceNextIndex)

		_, err = startResending(aliceThinClient,
			nil, aliceWriteCap, nil, &replyIndex,
			aliceEnvDesc, aliceCiphertext, aliceEnvHash)
		require.NoError(t, err)

		aliceCurrentIndex = aliceNextIndex
	}

	// Wait for propagation
	time.Sleep(30 * time.Second)

	// Bob reads ALL messages
	bobCurrentIndex := aliceFirstIndex

	for i := 0; i < numMessages; i++ {

		bobCiphertext, bobEnvDesc, bobEnvHash, bobNextIndex, err := bobThinClient.EncryptRead(bobReadCap, bobCurrentIndex)
		require.NoError(t, err)
		require.NotEmpty(t, bobCiphertext)
		require.NotNil(t, bobNextIndex)
		bobCurrentIndexBytes, err := bobCurrentIndex.MarshalBinary()
		require.NoError(t, err)

		bobResult, err := startResending(bobThinClient,
			bobReadCap, nil, bobCurrentIndexBytes, &replyIndex,
			bobEnvDesc, bobCiphertext, bobEnvHash)
		require.NoError(t, err)
		require.NotEmpty(t, bobResult.Plaintext)

		require.Equal(t, []byte(messages[i]), bobResult.Plaintext, "Message %d mismatch", i+1)

		bobCurrentIndex = bobNextIndex
	}

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
	skipInShortMode(t)
	t.Parallel()
	// Setup Alice and Bob thin clients
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	requireSharedPKIDocument(t, aliceThinClient, bobThinClient)

	// Step 1: Alice creates destination WriteCap for the final payload
	destSeed := make([]byte, 32)
	_, err := rand.Reader.Read(destSeed)
	require.NoError(t, err)

	destWriteCap, bobReadCap, destFirstIndex, err := aliceThinClient.NewKeypair(destSeed)
	require.NoError(t, err)
	require.NotNil(t, destWriteCap, "Destination WriteCap is nil")
	require.NotNil(t, bobReadCap, "Bob ReadCap is nil")

	// Step 2: Alice creates temporary copy stream
	tempSeed := make([]byte, 32)
	_, err = rand.Reader.Read(tempSeed)
	require.NoError(t, err)

	tempWriteCap, _, tempFirstIndex, err := aliceThinClient.NewKeypair(tempSeed)
	require.NoError(t, err)
	require.NotNil(t, tempWriteCap, "Temp WriteCap is nil")

	// Step 3: Create a large payload that will be chunked
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

	// Step 4: Create copy stream chunks from the large payload
	copyStreamChunks, _, err := aliceThinClient.CreateCourierEnvelopesFromPayload(largePayload, destWriteCap, destFirstIndex, true /* isStart */, true /* isLast */)
	require.NoError(t, err)
	require.NotEmpty(t, copyStreamChunks, "CreateCourierEnvelopesFromPayload returned empty chunks")
	numChunks := len(copyStreamChunks)

	// Print the destination box IDs for each chunk
	currentDestIndex := destFirstIndex
	for i := 0; i < numChunks; i++ {
		boxID, err := currentDestIndex.BoxIDForContext(bobReadCap, constants.PIGEONHOLE_CTX)
		require.NoError(t, err)
		t.Logf("Chunk %d/%d: Box ID = %x", i+1, numChunks, boxID.Bytes())
		currentDestIndex, err = aliceThinClient.NextMessageBoxIndex(currentDestIndex)
		require.NoError(t, err)
	}

	// Step 5: Write all copy stream chunks to the temporary copy stream
	tempIndex := tempFirstIndex
	replyIndex := uint8(0)

	for i, chunk := range copyStreamChunks {

		// Encrypt the chunk for the copy stream
		ciphertext, envDesc, envHash, nextTempIndex, err := aliceThinClient.EncryptWrite(chunk, tempWriteCap, tempIndex)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext, "EncryptWrite returned empty ciphertext for chunk %d", i+1)
		require.NotNil(t, nextTempIndex)

		// Send the encrypted chunk to the copy stream
		_, err = startResending(aliceThinClient,
			nil, tempWriteCap, nil, &replyIndex,
			envDesc, ciphertext, envHash)
		require.NoError(t, err)

		tempIndex = nextTempIndex
	}

	// Wait for all chunks to propagate to the copy stream
	time.Sleep(30 * time.Second)

	// Step 6: Send Copy command to courier using ARQ
	err = aliceThinClient.StartResendingCopyCommand(tempWriteCap)
	require.NoError(t, err)

	// Step 7: Bob reads chunks until we have the full payload (based on length prefix)
	bobIndex := destFirstIndex
	var reconstructedPayload []byte
	var expectedLength uint32
	chunkNum := 0

	for {
		chunkNum++

		// Bob encrypts read request
		bobCiphertext, bobEnvDesc, bobEnvHash, bobNextIndex, err := bobThinClient.EncryptRead(bobReadCap, bobIndex)
		require.NoError(t, err)
		require.NotEmpty(t, bobCiphertext, "Bob: EncryptRead returned empty ciphertext")
		require.NotNil(t, bobNextIndex)
		bobIndexBytes, err := bobIndex.MarshalBinary()
		require.NoError(t, err)

		// Bob sends read request and receives chunk
		bobResult, err := startResending(bobThinClient,
			bobReadCap, nil, bobIndexBytes, &replyIndex,
			bobEnvDesc, bobCiphertext, bobEnvHash)
		require.NoError(t, err)
		require.NotEmpty(t, bobResult.Plaintext, "Bob: Failed to receive chunk %d", chunkNum)

		// Append chunk to reconstructed payload
		reconstructedPayload = append(reconstructedPayload, bobResult.Plaintext...)

		// Extract expected length from the first 4 bytes once we have them
		if expectedLength == 0 && len(reconstructedPayload) >= 4 {
			expectedLength = binary.BigEndian.Uint32(reconstructedPayload[:4])
		}

		// Check if we have the full payload (4 byte prefix + expectedLength bytes)
		if expectedLength > 0 && uint32(len(reconstructedPayload)) >= expectedLength+4 {
			break
		}

		bobIndex = bobNextIndex
	}

	// Verify the reconstructed payload matches the original
	require.Equal(t, largePayload, reconstructedPayload, "Reconstructed payload doesn't match original")
}

// TestCopyCommandMultiChannel tests the Copy Command API with multiple destination channels:
// 1. Alice creates two destination channels (chan1 and chan2)
// 2. Alice creates a temporary copy stream channel
// 3. Alice creates two payloads - one for each destination channel
// 4. Alice calls CreateCourierEnvelopesFromPayload twice with different WriteCaps
// 5. Alice writes all copy stream chunks to the temporary channel
// 6. Alice sends the Copy command to the courier
// 7. Bob reads from both destination channels and verifies the payloads
//
// This test verifies:
// - The Copy Command API can atomically write to multiple destination channels
// - Multiple calls to CreateCourierEnvelopesFromPayload work correctly
// - The courier processes all envelopes and writes to the correct destinations
func TestCopyCommandMultiChannel(t *testing.T) {
	skipInShortMode(t)
	t.Parallel()
	// Setup Alice and Bob thin clients
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	requireSharedPKIDocument(t, aliceThinClient, bobThinClient)

	// Step 1: Alice creates two destination channels

	// Channel 1
	chan1Seed := make([]byte, 32)
	_, err := rand.Reader.Read(chan1Seed)
	require.NoError(t, err)
	chan1WriteCap, chan1ReadCap, chan1FirstIndex, err := aliceThinClient.NewKeypair(chan1Seed)
	require.NoError(t, err)
	require.NotNil(t, chan1WriteCap, "Channel 1 WriteCap is nil")
	require.NotNil(t, chan1ReadCap, "Channel 1 ReadCap is nil")

	// Channel 2
	chan2Seed := make([]byte, 32)
	_, err = rand.Reader.Read(chan2Seed)
	require.NoError(t, err)
	chan2WriteCap, chan2ReadCap, chan2FirstIndex, err := aliceThinClient.NewKeypair(chan2Seed)
	require.NoError(t, err)
	require.NotNil(t, chan2WriteCap, "Channel 2 WriteCap is nil")
	require.NotNil(t, chan2ReadCap, "Channel 2 ReadCap is nil")

	// Step 2: Alice creates temporary copy stream
	tempSeed := make([]byte, 32)
	_, err = rand.Reader.Read(tempSeed)
	require.NoError(t, err)
	tempWriteCap, _, tempFirstIndex, err := aliceThinClient.NewKeypair(tempSeed)
	require.NoError(t, err)
	require.NotNil(t, tempWriteCap, "Temp WriteCap is nil")

	// Step 3: Create two payloads - one for each destination channel

	// Payload 1 for Channel 1
	payload1 := []byte("This is the secret message for Channel 1. It contains important information.")

	// Payload 2 for Channel 2
	payload2 := []byte("This is the confidential data for Channel 2. Handle with care and discretion.")

	// Step 4: Create copy stream chunks for both channels

	// First call: payload1 -> channel 1 (isStart=true, isLast=false)
	chunks1, _, err := aliceThinClient.CreateCourierEnvelopesFromPayload(payload1, chan1WriteCap, chan1FirstIndex, true, false)
	require.NoError(t, err)
	require.NotEmpty(t, chunks1, "CreateCourierEnvelopesFromPayload returned empty chunks for channel 1")

	// Second call: payload2 -> channel 2 (isStart=false, isLast=true)
	chunks2, _, err := aliceThinClient.CreateCourierEnvelopesFromPayload(payload2, chan2WriteCap, chan2FirstIndex, false, true)
	require.NoError(t, err)
	require.NotEmpty(t, chunks2, "CreateCourierEnvelopesFromPayload returned empty chunks for channel 2")

	// Combine all chunks
	allChunks := append(chunks1, chunks2...)

	// Step 5: Write all copy stream chunks to the temporary channel
	tempIndex := tempFirstIndex
	replyIndex := uint8(0)

	for i, chunk := range allChunks {

		// Encrypt the chunk for the copy stream
		ciphertext, envDesc, envHash, nextTempIndex, err := aliceThinClient.EncryptWrite(chunk, tempWriteCap, tempIndex)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext, "EncryptWrite returned empty ciphertext for chunk %d", i+1)
		require.NotNil(t, nextTempIndex)

		// Send the encrypted chunk to the copy stream
		_, err = startResending(aliceThinClient,
			nil, tempWriteCap, nil, &replyIndex,
			envDesc, ciphertext, envHash)
		require.NoError(t, err)

		tempIndex = nextTempIndex
	}

	// Wait for chunks to propagate
	time.Sleep(30 * time.Second)

	// Step 6: Send Copy command to courier using ARQ
	err = aliceThinClient.StartResendingCopyCommand(tempWriteCap)
	require.NoError(t, err)

	// Step 7: Bob reads from both channels and verifies payloads

	// Read from Channel 1
	bob1Ciphertext, bob1EnvDesc, bob1EnvHash, _, err := bobThinClient.EncryptRead(chan1ReadCap, chan1FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 1")
	chan1FirstIndexBytes, err := chan1FirstIndex.MarshalBinary()
	require.NoError(t, err)

	bob1Result, err := startResending(bobThinClient,
		chan1ReadCap, nil, chan1FirstIndexBytes, &replyIndex,
		bob1EnvDesc, bob1Ciphertext, bob1EnvHash)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Result.Plaintext, "Bob: Failed to receive data from Channel 1")

	// Verify Channel 1 payload
	require.Equal(t, payload1, bob1Result.Plaintext, "Channel 1 payload doesn't match")

	// Read from Channel 2
	bob2Ciphertext, bob2EnvDesc, bob2EnvHash, _, err := bobThinClient.EncryptRead(chan2ReadCap, chan2FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 2")
	chan2FirstIndexBytes, err := chan2FirstIndex.MarshalBinary()
	require.NoError(t, err)

	bob2Result, err := startResending(bobThinClient,
		chan2ReadCap, nil, chan2FirstIndexBytes, &replyIndex,
		bob2EnvDesc, bob2Ciphertext, bob2EnvHash)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Result.Plaintext, "Bob: Failed to receive data from Channel 2")

	// Verify Channel 2 payload
	require.Equal(t, payload2, bob2Result.Plaintext, "Channel 2 payload doesn't match")

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
	skipInShortMode(t)
	t.Parallel()
	// Setup Alice and Bob thin clients
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	requireSharedPKIDocument(t, aliceThinClient, bobThinClient)

	// Step 1: Alice creates two destination channels

	// Channel 1
	chan1Seed := make([]byte, 32)
	_, err := rand.Reader.Read(chan1Seed)
	require.NoError(t, err)
	chan1WriteCap, chan1ReadCap, chan1FirstIndex, err := aliceThinClient.NewKeypair(chan1Seed)
	require.NoError(t, err)
	require.NotNil(t, chan1WriteCap, "Channel 1 WriteCap is nil")
	require.NotNil(t, chan1ReadCap, "Channel 1 ReadCap is nil")

	// Channel 2
	chan2Seed := make([]byte, 32)
	_, err = rand.Reader.Read(chan2Seed)
	require.NoError(t, err)
	chan2WriteCap, chan2ReadCap, chan2FirstIndex, err := aliceThinClient.NewKeypair(chan2Seed)
	require.NoError(t, err)
	require.NotNil(t, chan2WriteCap, "Channel 2 WriteCap is nil")
	require.NotNil(t, chan2ReadCap, "Channel 2 ReadCap is nil")

	// Step 2: Alice creates temporary copy stream
	tempSeed := make([]byte, 32)
	_, err = rand.Reader.Read(tempSeed)
	require.NoError(t, err)
	tempWriteCap, _, tempFirstIndex, err := aliceThinClient.NewKeypair(tempSeed)
	require.NoError(t, err)
	require.NotNil(t, tempWriteCap, "Temp WriteCap is nil")

	// Step 3: Create two payloads - one for each destination channel

	// Payload 1 for Channel 1
	payload1 := []byte("This is the secret message for Channel 1 using the efficient multi-channel API.")

	// Payload 2 for Channel 2
	payload2 := []byte("This is the confidential data for Channel 2 packed efficiently with payload1.")

	// Step 4: Create copy stream chunks using CreateCourierEnvelopesFromMultiPayload (efficient API)

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
	allChunksResult, err := aliceThinClient.CreateCourierEnvelopesFromMultiPayload(destinations, true, true, nil)
	require.NoError(t, err)
	require.NotEmpty(t, allChunksResult.Envelopes, "CreateCourierEnvelopesFromMultiPayload returned empty chunks")

	// Step 5: Write all copy stream chunks to the temporary channel
	tempIndex := tempFirstIndex
	replyIndex := uint8(0)

	for i, chunk := range allChunksResult.Envelopes {

		// Encrypt the chunk for the copy stream
		ciphertext, envDesc, envHash, nextTempIndex, err := aliceThinClient.EncryptWrite(chunk, tempWriteCap, tempIndex)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext, "EncryptWrite returned empty ciphertext for chunk %d", i+1)
		require.NotNil(t, nextTempIndex)

		// Send the encrypted chunk to the copy stream
		_, err = startResending(aliceThinClient,
			nil, tempWriteCap, nil, &replyIndex,
			envDesc, ciphertext, envHash)
		require.NoError(t, err)

		tempIndex = nextTempIndex
	}

	// Wait for chunks to propagate
	time.Sleep(30 * time.Second)

	// Step 6: Send Copy command to courier using ARQ
	err = aliceThinClient.StartResendingCopyCommand(tempWriteCap)
	require.NoError(t, err)

	// Step 7: Bob reads from both channels and verifies payloads

	// Read from Channel 1
	bob1Ciphertext, bob1EnvDesc, bob1EnvHash, _, err := bobThinClient.EncryptRead(chan1ReadCap, chan1FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 1")
	chan1FirstIndexBytes, err := chan1FirstIndex.MarshalBinary()
	require.NoError(t, err)

	bob1Result, err := startResending(bobThinClient,
		chan1ReadCap, nil, chan1FirstIndexBytes, &replyIndex,
		bob1EnvDesc, bob1Ciphertext, bob1EnvHash)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Result.Plaintext, "Bob: Failed to receive data from Channel 1")

	// Verify Channel 1 payload
	require.Equal(t, payload1, bob1Result.Plaintext, "Channel 1 payload doesn't match")

	// Read from Channel 2
	bob2Ciphertext, bob2EnvDesc, bob2EnvHash, _, err := bobThinClient.EncryptRead(chan2ReadCap, chan2FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Ciphertext, "Bob: EncryptRead returned empty ciphertext for Channel 2")
	chan2FirstIndexBytes, err := chan2FirstIndex.MarshalBinary()
	require.NoError(t, err)

	bob2Result, err := startResending(bobThinClient,
		chan2ReadCap, nil, chan2FirstIndexBytes, &replyIndex,
		bob2EnvDesc, bob2Ciphertext, bob2EnvHash)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Result.Plaintext, "Bob: Failed to receive data from Channel 2")

	// Verify Channel 2 payload
	require.Equal(t, payload2, bob2Result.Plaintext, "Channel 2 payload doesn't match")

}

// TestTombstoning tests the tombstoning API:
// 1. Alice writes a message to a box
// 2. Bob reads and verifies the message
// 3. Alice tombstones the box (deletes it with an empty payload)
// 4. Bob reads again and verifies the tombstone
func TestTombstoning(t *testing.T) {
	skipInShortMode(t)
	t.Parallel()
	alice := setupThinClient(t)
	defer alice.Close()
	bob := setupThinClient(t)
	defer bob.Close()

	// Create keypair
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	writeCap, readCap, firstIndex, err := alice.NewKeypair(seed)
	require.NoError(t, err)

	// Step 1: Alice writes a message
	message := []byte("Secret message that will be tombstoned")
	ciphertext, envDesc, envHash, _, err := alice.EncryptWrite(message, writeCap, firstIndex)
	require.NoError(t, err)

	replyIndex := uint8(0)
	_, err = startResending(alice, nil, writeCap, nil, &replyIndex, envDesc, ciphertext, envHash)
	require.NoError(t, err)

	time.Sleep(30 * time.Second)

	// Step 2: Bob reads and verifies
	ciphertext, envDesc, envHash, _, err = bob.EncryptRead(readCap, firstIndex)
	require.NoError(t, err)
	firstIndexBytes, err := firstIndex.MarshalBinary()
	require.NoError(t, err)
	readResult, err := startResending(bob, readCap, nil, firstIndexBytes, &replyIndex, envDesc, ciphertext, envHash)
	require.NoError(t, err)
	require.Equal(t, message, readResult.Plaintext)

	// Step 3: Alice tombstones the box using TombstoneRange with count=1
	tombResult, err := alice.TombstoneRange(writeCap, firstIndex, 1)
	require.NoError(t, err)
	require.Len(t, tombResult.Envelopes, 1)
	tombEnvelope := tombResult.Envelopes[0]
	_, err = startResending(alice, nil, writeCap, nil, nil, tombEnvelope.EnvelopeDescriptor, tombEnvelope.MessageCiphertext, tombEnvelope.EnvelopeHash)
	require.NoError(t, err)

	// Step 4: Bob polls for tombstone with retries
	const maxAttempts = 6
	const pollInterval = 10 * time.Second
	var tombstoneVerified bool

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		t.Logf("Polling for tombstone (attempt %d/%d)...", attempt, maxAttempts)
		time.Sleep(pollInterval)

		ciphertext, envDesc, envHash, _, err = bob.EncryptRead(readCap, firstIndex)
		require.NoError(t, err)
		_, err = startResending(bob, readCap, nil, firstIndexBytes, &replyIndex, envDesc, ciphertext, envHash)
		if errors.Is(err, thin.ErrTombstone) {
			tombstoneVerified = true
			break
		}
	}

	require.True(t, tombstoneVerified, "Tombstone not propagated after %d attempts", maxAttempts)
}

// TestTombstoneRange tests the TombstoneRange API:
// 1. Alice writes multiple messages to consecutive boxes
// 2. Bob reads and verifies each message
// 3. Alice tombstones all boxes using TombstoneRange
// 4. Bob reads again and verifies all boxes are tombstoned
func TestTombstoneRange(t *testing.T) {
	skipInShortMode(t)
	t.Parallel()
	alice := setupThinClient(t)
	defer alice.Close()
	bob := setupThinClient(t)
	defer bob.Close()

	// Create keypair
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	writeCap, readCap, firstIndex, err := alice.NewKeypair(seed)
	require.NoError(t, err)

	// Write 3 messages to consecutive boxes
	const numMessages = 3
	messages := [][]byte{
		[]byte("Message 1 - will be tombstoned"),
		[]byte("Message 2 - will be tombstoned"),
		[]byte("Message 3 - will be tombstoned"),
	}

	writeIdx := firstIndex
	replyIndex := uint8(0)
	for _, msg := range messages {
		ciphertext, envDesc, envHash, nextWriteIdx, err := alice.EncryptWrite(msg, writeCap, writeIdx)
		require.NoError(t, err)
		require.NotNil(t, nextWriteIdx)
		_, err = startResending(alice, nil, writeCap, nil, &replyIndex, envDesc, ciphertext, envHash)
		require.NoError(t, err)

		writeIdx = nextWriteIdx
	}

	time.Sleep(30 * time.Second)

	// Bob reads and verifies all messages
	readIdx := firstIndex
	for _, expectedMsg := range messages {
		ciphertext, envDesc, envHash, nextReadIdx, err := bob.EncryptRead(readCap, readIdx)
		require.NoError(t, err)
		require.NotNil(t, nextReadIdx)
		readIdxBytes, err := readIdx.MarshalBinary()
		require.NoError(t, err)
		readResult, err := startResending(bob, readCap, nil, readIdxBytes, &replyIndex, envDesc, ciphertext, envHash)
		require.NoError(t, err)
		require.Equal(t, expectedMsg, readResult.Plaintext)

		readIdx = nextReadIdx
	}

	// Alice tombstones all boxes using TombstoneRange
	result, err := alice.TombstoneRange(writeCap, firstIndex, numMessages)
	require.NoError(t, err)
	require.Len(t, result.Envelopes, numMessages)

	// Send all tombstone envelopes
	for _, envelope := range result.Envelopes {
		_, err = startResending(alice,
			nil, writeCap, nil, nil,
			envelope.EnvelopeDescriptor, envelope.MessageCiphertext, envelope.EnvelopeHash,
		)
		require.NoError(t, err)
	}

	time.Sleep(60 * time.Second)

	// Bob reads again and verifies all boxes are tombstoned
	readIdx = firstIndex
	for i := 0; i < numMessages; i++ {
		ciphertext, envDesc, envHash, nextReadIdx, err := bob.EncryptRead(readCap, readIdx)
		require.NoError(t, err)
		require.NotNil(t, nextReadIdx)
		readIdxBytes, err := readIdx.MarshalBinary()
		require.NoError(t, err)
		_, err = startResending(bob, readCap, nil, readIdxBytes, &replyIndex, envDesc, ciphertext, envHash)
		require.True(t, errors.Is(err, thin.ErrTombstone), "Expected ErrTombstone for box %d, got: %v", i+1, err)

		readIdx = nextReadIdx
	}

}

// TestBoxIDNotFoundError tests that we receive an ErrBoxIDNotFound error
// when attempting to read from a box that has never been written to.
//
// This test verifies:
// - Reading from a non-existent box returns ErrBoxIDNotFound
// - The error can be checked using errors.Is()
func TestBoxIDNotFoundError(t *testing.T) {
	skipInShortMode(t)
	t.Parallel()
	// Setup Bob thin client (reader)
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	// Validate PKI document
	validatePKIDocument(t, bobThinClient)

	// Create a new keypair - but we will NOT write any message to it
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	_, readCap, firstIndex, err := bobThinClient.NewKeypair(seed)
	require.NoError(t, err)
	require.NotNil(t, readCap, "ReadCap should not be nil")

	// Attempt to read from the non-existent box
	bobCiphertext, bobEnvDesc, bobEnvHash, _, err := bobThinClient.EncryptRead(readCap, firstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bobCiphertext, "EncryptRead should return ciphertext")
	firstIndexBytes, err := firstIndex.MarshalBinary()
	require.NoError(t, err)

	// Send the read request - this should fail with ErrBoxIDNotFound
	// Use StartResendingEncryptedMessageNoRetry to get immediate error without retries
	replyIndex := uint8(0)
	_, err = bobThinClient.StartResendingEncryptedMessageNoRetry(
		readCap,         // readCap
		nil,             // writeCap (nil for read operations)
		firstIndexBytes, // messageBoxIndex
		&replyIndex,     // replyIndex
		bobEnvDesc,      // envelopeDescriptor
		bobCiphertext,   // messageCiphertext
		bobEnvHash,      // envelopeHash
	)

	// Verify we got the expected ErrBoxIDNotFound error
	require.Error(t, err, "Expected an error when reading from non-existent box")
	require.ErrorIs(t, err, thin.ErrBoxIDNotFound, "Expected ErrBoxIDNotFound error, got: %v", err)

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
	skipInShortMode(t)
	t.Parallel()
	// Setup Alice and Bob thin clients
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	requireSharedPKIDocument(t, aliceThinClient, bobThinClient)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Create keypair - Alice gets WriteCap, Bob gets ReadCap, both target same box
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	aliceWriteCap, bobReadCap, firstIndex, err := aliceThinClient.NewKeypair(seed)
	require.NoError(t, err)
	require.NotNil(t, aliceWriteCap, "Alice: WriteCap is nil")
	require.NotNil(t, bobReadCap, "Bob: ReadCap is nil")

	// Log the box ID both will be using
	boxID, err := firstIndex.BoxIDForContext(bobReadCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	t.Logf("Shared Box ID: %x", boxID.Bytes())

	// Channel to receive Bob's read result
	type readResult struct {
		plaintext []byte
		err       error
	}
	bobResultChan := make(chan readResult, 1)

	// Start Bob's read in a goroutine BEFORE Alice writes
	// This read will initially fail with BoxIDNotFound, but should retry
	go func() {
		// Encrypt Bob's read request
		bobCiphertext, bobEnvDesc, bobEnvHash, _, err := bobThinClient.EncryptRead(bobReadCap, firstIndex)
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
		result, err := startResending(bobThinClient,
			bobReadCap,      // readCap
			nil,             // writeCap (nil for read operations)
			firstIndexBytes, // messageBoxIndex
			&replyIndex,     // replyIndex
			bobEnvDesc,      // envelopeDescriptor
			bobCiphertext,   // messageCiphertext
			bobEnvHash,      // envelopeHash
		)
		var pt []byte
		if result != nil {
			pt = result.Plaintext
		}
		bobResultChan <- readResult{pt, err}
	}()

	// Wait a bit to ensure Bob's read is in-flight and retrying
	time.Sleep(5 * time.Second)

	// Alice writes the message
	aliceMessage := []byte("Hello Bob! I wrote this after you started reading.")

	aliceCiphertext, aliceEnvDesc, aliceEnvHash, _, err := aliceThinClient.EncryptWrite(aliceMessage, aliceWriteCap, firstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, aliceCiphertext, "Alice: EncryptWrite returned empty ciphertext")

	replyIndex := uint8(0)
	_, err = startResending(aliceThinClient,
		nil,             // readCap (nil for write operations)
		aliceWriteCap,   // writeCap
		nil,             // messageBoxIndex (not needed for writes)
		&replyIndex,     // replyIndex
		aliceEnvDesc,    // envelopeDescriptor
		aliceCiphertext, // messageCiphertext
		aliceEnvHash,    // envelopeHash
	)
	require.NoError(t, err)

	// Wait for Bob's read to complete
	select {
	case result := <-bobResultChan:
		require.NoError(t, result.err, "Bob's read should eventually succeed after Alice's write")
		require.NotEmpty(t, result.plaintext, "Bob should receive the message")
		require.Equal(t, aliceMessage, result.plaintext, "Bob's decrypted message should match Alice's original")

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
	skipInShortMode(t)
	t.Parallel()
	// Setup thin client
	thinClient := setupThinClient(t)
	defer thinClient.Close()

	// Validate PKI document
	validatePKIDocument(t, thinClient)

	// Create a new keypair
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	writeCap, _, firstIndex, err := thinClient.NewKeypair(seed)
	require.NoError(t, err)
	require.NotNil(t, writeCap, "WriteCap should not be nil")

	// First write - should succeed
	message1 := []byte("First message - this should work")
	ciphertext1, envDesc1, envHash1, _, err := thinClient.EncryptWrite(message1, writeCap, firstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext1, "EncryptWrite should return ciphertext")

	// Send the first write
	_, err = startResending(thinClient,
		nil,         // readCap (nil for write operations)
		writeCap,    // writeCap
		nil,         // messageBoxIndex (nil for write operations)
		nil,         // replyIndex (nil for write operations)
		envDesc1,    // envelopeDescriptor
		ciphertext1, // messageCiphertext
		envHash1,    // envelopeHash
	)
	require.NoError(t, err, "First write should succeed")

	// Wait for propagation to ensure the first write is fully replicated
	time.Sleep(5 * time.Second)

	// Second write to the SAME box - should fail with ErrBoxAlreadyExists
	message2 := []byte("Second message - this should fail")
	ciphertext2, envDesc2, envHash2, _, err := thinClient.EncryptWrite(message2, writeCap, firstIndex)
	require.NoError(t, err, "EncryptWrite should succeed even for duplicate")

	// Send the second write - should fail with BoxAlreadyExists
	// Use StartResendingEncryptedMessageReturnBoxExists to get the error instead of
	// treating it as idempotent success
	_, err = thinClient.StartResendingEncryptedMessageReturnBoxExists(
		nil,         // readCap
		writeCap,    // writeCap
		nil,         // messageBoxIndex
		nil,         // replyIndex
		envDesc2,    // envelopeDescriptor
		ciphertext2, // messageCiphertext
		envHash2,    // envelopeHash
	)

	// Verify we got the expected ErrBoxAlreadyExists error
	require.Error(t, err, "Expected an error when writing to existing box")
	require.ErrorIs(t, err, thin.ErrBoxAlreadyExists, "Expected ErrBoxAlreadyExists error, got: %v", err)

}

func TestCopyOntoAlreadyExistingBoxError(t *testing.T) {
	skipInShortMode(t)
	t.Parallel()
	// Setup thin client
	thinClient := setupThinClient(t)
	defer thinClient.Close()

	// Validate PKI document
	validatePKIDocument(t, thinClient)

	// Create a new keypair
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	writeCap, _, firstIndex, err := thinClient.NewKeypair(seed)
	require.NoError(t, err)
	require.NotNil(t, writeCap, "WriteCap should not be nil")

	// First write - should succeed
	message1 := []byte("First message - this should work")
	ciphertext1, envDesc1, envHash1, _, err := thinClient.EncryptWrite(message1, writeCap, firstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext1, "EncryptWrite should return ciphertext")

	// Send the first write
	_, err = startResending(thinClient,
		nil,         // readCap (nil for write operations)
		writeCap,    // writeCap
		nil,         // messageBoxIndex (nil for write operations)
		nil,         // replyIndex (nil for write operations)
		envDesc1,    // envelopeDescriptor
		ciphertext1, // messageCiphertext
		envHash1,    // envelopeHash
	)
	require.NoError(t, err, "First write should succeed")

	// Wait for propagation to ensure the first write is fully replicated
	time.Sleep(5 * time.Second)

	// Compose copy temp stream
	tempSeed := make([]byte, 32)
	_, err = rand.Reader.Read(tempSeed)
	require.NoError(t, err)

	tempWriteCap, _, tempFirstIndex, err := thinClient.NewKeypair(tempSeed)
	require.NoError(t, err)
	require.NotNil(t, tempWriteCap, "Temp WriteCap is nil")

	largePayload := make([]byte, 2000)
	_, err = rand.Reader.Read(largePayload)
	require.NoError(t, err)

	copyStreamChunks, _, err := thinClient.CreateCourierEnvelopesFromPayload(largePayload, writeCap, firstIndex, true /* isStart */, true /* isLast */)
	require.NoError(t, err)
	require.NotEmpty(t, copyStreamChunks, "CreateCourierEnvelopesFromPayload returned empty chunks")

	tempIndex := tempFirstIndex
	replyIndex := uint8(0)

	for i, chunk := range copyStreamChunks {

		// Encrypt the chunk for the copy stream
		ciphertext, envDesc, envHash, nextTempIndex, err := thinClient.EncryptWrite(chunk, tempWriteCap, tempIndex)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext, "EncryptWrite returned empty ciphertext for chunk %d", i+1)
		require.NotNil(t, nextTempIndex)

		// Send the encrypted chunk to the copy stream
		_, err = startResending(thinClient,
			nil, tempWriteCap, nil, &replyIndex,
			envDesc, ciphertext, envHash)
		require.NoError(t, err)

		tempIndex = nextTempIndex
	}

	// Wait for all chunks to propagate to the copy stream
	time.Sleep(30 * time.Second)

	err = thinClient.StartResendingCopyCommand(tempWriteCap)
	require.Error(t, err)
}

// TestFromPayloadMultiCall tests calling CreateCourierEnvelopesFromPayload multiple times
// to send a large payload to a single destination stream.
//
// This exercises the stateless API: no streamID, explicit isStart/isLast flags,
// and NextDestIndex returned in the reply so the caller never does index math.
//
// Flow:
// 1. Alice creates a destination channel and a temp copy stream channel
// 2. Alice splits a payload (3x box payload size) into 3 chunks
// 3. Alice calls CreateCourierEnvelopesFromPayload 3 times, using NextDestIndex from each reply
// 4. Alice writes all temp stream elements and sends the copy command
// 5. Bob reads from the destination channel and verifies the reconstructed payload
func TestFromPayloadMultiCall(t *testing.T) {
	skipInShortMode(t)
	t.Parallel()
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	requireSharedPKIDocument(t, aliceThinClient, bobThinClient)

	// Create destination channel
	destSeed := make([]byte, 32)
	_, err := rand.Reader.Read(destSeed)
	require.NoError(t, err)
	destWriteCap, bobReadCap, destFirstIndex, err := aliceThinClient.NewKeypair(destSeed)
	require.NoError(t, err)

	// Create temp copy stream channel
	tempSeed := make([]byte, 32)
	_, err = rand.Reader.Read(tempSeed)
	require.NoError(t, err)
	tempWriteCap, _, tempFirstIndex, err := aliceThinClient.NewKeypair(tempSeed)
	require.NoError(t, err)

	// Use pigeonhole geometry to size the payload: 3x the max box payload
	// so each chunk fills exactly one destination box.
	maxPayload := aliceThinClient.GetPigeonholeGeometry().MaxPlaintextPayloadLength
	t.Logf("MaxPlaintextPayloadLength = %d bytes", maxPayload)
	chunkSize := maxPayload
	fullPayload := make([]byte, 3*chunkSize)
	_, err = rand.Reader.Read(fullPayload)
	require.NoError(t, err)

	chunk1 := fullPayload[:chunkSize]
	chunk2 := fullPayload[chunkSize : 2*chunkSize]
	chunk3 := fullPayload[2*chunkSize:]

	// Call CreateCourierEnvelopesFromPayload 3 times using the new stateless API.
	// No streamID. Explicit isStart/isLast. NextDestIndex in reply.
	var allTempElements [][]byte
	destIndex := destFirstIndex

	// First call: isStart=true, isLast=false
	envelopes1, nextDest1, err := aliceThinClient.CreateCourierEnvelopesFromPayload(
		chunk1, destWriteCap, destIndex, true, false)
	require.NoError(t, err)
	require.NotEmpty(t, envelopes1)
	require.NotNil(t, nextDest1)
	allTempElements = append(allTempElements, envelopes1...)

	// Second call: isStart=false, isLast=false — uses NextDestIndex from reply
	envelopes2, nextDest2, err := aliceThinClient.CreateCourierEnvelopesFromPayload(
		chunk2, destWriteCap, nextDest1, false, false)
	require.NoError(t, err)
	require.NotEmpty(t, envelopes2)
	require.NotNil(t, nextDest2)
	allTempElements = append(allTempElements, envelopes2...)

	// Third call: isStart=false, isLast=true
	envelopes3, nextDest3, err := aliceThinClient.CreateCourierEnvelopesFromPayload(
		chunk3, destWriteCap, nextDest2, false, true)
	require.NoError(t, err)
	require.NotEmpty(t, envelopes3)
	require.NotNil(t, nextDest3)
	allTempElements = append(allTempElements, envelopes3...)

	// Write all temp stream elements
	tempIndex := tempFirstIndex
	replyIndex := uint8(0)
	for _, elem := range allTempElements {
		ciphertext, envDesc, envHash, nextTempIndex, err := aliceThinClient.EncryptWrite(elem, tempWriteCap, tempIndex)
		require.NoError(t, err)
		require.NotNil(t, nextTempIndex)
		_, err = startResending(aliceThinClient,
			nil, tempWriteCap, nil, &replyIndex,
			envDesc, ciphertext, envHash)
		require.NoError(t, err)
		tempIndex = nextTempIndex
	}

	time.Sleep(30 * time.Second)

	// Send copy command
	err = aliceThinClient.StartResendingCopyCommand(tempWriteCap)
	require.NoError(t, err)

	// Bob reads all destination boxes and reconstructs the payload
	bobIndex := destFirstIndex
	var reconstructed []byte
	reconstructDeadline := time.After(reconstructTimeout)
	for len(reconstructed) < len(fullPayload) {
		select {
		case <-reconstructDeadline:
			t.Fatalf("timed out reconstructing payload: got %d/%d bytes", len(reconstructed), len(fullPayload))
		default:
		}
		bobCiphertext, bobEnvDesc, bobEnvHash, bobNextIndex, err := bobThinClient.EncryptRead(bobReadCap, bobIndex)
		require.NoError(t, err)
		require.NotNil(t, bobNextIndex)
		bobIndexBytes, err := bobIndex.MarshalBinary()
		require.NoError(t, err)

		result, err := startResending(bobThinClient,
			bobReadCap, nil, bobIndexBytes, &replyIndex,
			bobEnvDesc, bobCiphertext, bobEnvHash)
		require.NoError(t, err)
		require.NotEmpty(t, result.Plaintext)
		reconstructed = append(reconstructed, result.Plaintext...)

		bobIndex = bobNextIndex
	}

	require.Equal(t, fullPayload, reconstructed, "Reconstructed payload doesn't match original")
}

// TestFromMultiPayloadMultiCall tests calling CreateCourierEnvelopesFromMultiPayload
// multiple times, writing to two destination channels across two calls.
//
// This exercises the stateful API with NextDestIndices in the reply so the caller
// can continue writing to the same destinations without index math.
//
// Flow:
// 1. Alice creates two destination channels and a temp copy stream channel
// 2. Alice calls CreateCourierEnvelopesFromMultiPayload twice with the same streamID
// 3. The second call uses NextDestIndices from the first reply
// 4. Alice writes all temp stream elements and sends the copy command
// 5. Bob reads from both destination channels and verifies
func TestFromMultiPayloadMultiCall(t *testing.T) {
	skipInShortMode(t)
	t.Parallel()
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	requireSharedPKIDocument(t, aliceThinClient, bobThinClient)

	// Create two destination channels
	chan1Seed := make([]byte, 32)
	_, err := rand.Reader.Read(chan1Seed)
	require.NoError(t, err)
	chan1WriteCap, chan1ReadCap, chan1FirstIndex, err := aliceThinClient.NewKeypair(chan1Seed)
	require.NoError(t, err)

	chan2Seed := make([]byte, 32)
	_, err = rand.Reader.Read(chan2Seed)
	require.NoError(t, err)
	chan2WriteCap, chan2ReadCap, chan2FirstIndex, err := aliceThinClient.NewKeypair(chan2Seed)
	require.NoError(t, err)

	// Create temp copy stream channel
	tempSeed := make([]byte, 32)
	_, err = rand.Reader.Read(tempSeed)
	require.NoError(t, err)
	tempWriteCap, _, tempFirstIndex, err := aliceThinClient.NewKeypair(tempSeed)
	require.NoError(t, err)

	// Use pigeonhole geometry to size payloads: each payload is exactly one box payload
	// so each call writes one destination box per channel.
	maxPayload := aliceThinClient.GetPigeonholeGeometry().MaxPlaintextPayloadLength
	t.Logf("MaxPlaintextPayloadLength = %d bytes", maxPayload)

	payload1a := make([]byte, maxPayload)
	_, err = rand.Reader.Read(payload1a)
	require.NoError(t, err)
	payload2a := make([]byte, maxPayload)
	_, err = rand.Reader.Read(payload2a)
	require.NoError(t, err)
	payload1b := make([]byte, maxPayload)
	_, err = rand.Reader.Read(payload1b)
	require.NoError(t, err)
	payload2b := make([]byte, maxPayload)
	_, err = rand.Reader.Read(payload2b)
	require.NoError(t, err)

	// First call: two destinations, isStart=true, isLast=false, buffer=nil
	result1, err := aliceThinClient.CreateCourierEnvelopesFromMultiPayload([]thin.DestinationPayload{
		{Payload: payload1a, WriteCap: chan1WriteCap, StartIndex: chan1FirstIndex},
		{Payload: payload2a, WriteCap: chan2WriteCap, StartIndex: chan2FirstIndex},
	}, true, false, nil)
	require.NoError(t, err)
	require.NotEmpty(t, result1.Envelopes)
	require.Len(t, result1.NextDestIndices, 2)

	// Second call: continue where we left off, pass buffer, isStart=false, isLast=true
	result2, err := aliceThinClient.CreateCourierEnvelopesFromMultiPayload([]thin.DestinationPayload{
		{Payload: payload1b, WriteCap: chan1WriteCap, StartIndex: result1.NextDestIndices[0]},
		{Payload: payload2b, WriteCap: chan2WriteCap, StartIndex: result1.NextDestIndices[1]},
	}, false, true, result1.Buffer)
	require.NoError(t, err)
	require.NotEmpty(t, result2.Envelopes)
	require.Len(t, result2.NextDestIndices, 2)

	// Combine and write all temp stream elements
	allElements := append(result1.Envelopes, result2.Envelopes...)
	tempIndex := tempFirstIndex
	replyIndex := uint8(0)
	for _, elem := range allElements {
		ciphertext, envDesc, envHash, nextTempIndex, err := aliceThinClient.EncryptWrite(elem, tempWriteCap, tempIndex)
		require.NoError(t, err)
		require.NotNil(t, nextTempIndex)
		_, err = startResending(aliceThinClient,
			nil, tempWriteCap, nil, &replyIndex,
			envDesc, ciphertext, envHash)
		require.NoError(t, err)
		tempIndex = nextTempIndex
	}

	time.Sleep(30 * time.Second)

	// Send copy command
	err = aliceThinClient.StartResendingCopyCommand(tempWriteCap)
	require.NoError(t, err)

	// Bob reads from channel 1 — expects payload1a then payload1b
	expectedChan1 := append(payload1a, payload1b...)
	bobIndex := chan1FirstIndex
	var chan1Data []byte
	chan1Deadline := time.After(reconstructTimeout)
	for len(chan1Data) < len(expectedChan1) {
		select {
		case <-chan1Deadline:
			t.Fatalf("timed out reconstructing channel 1: got %d/%d bytes", len(chan1Data), len(expectedChan1))
		default:
		}
		bobCiphertext, bobEnvDesc, bobEnvHash, bobNextIndex, err := bobThinClient.EncryptRead(chan1ReadCap, bobIndex)
		require.NoError(t, err)
		require.NotNil(t, bobNextIndex)
		bobIndexBytes, err := bobIndex.MarshalBinary()
		require.NoError(t, err)
		result, err := startResending(bobThinClient,
			chan1ReadCap, nil, bobIndexBytes, &replyIndex,
			bobEnvDesc, bobCiphertext, bobEnvHash)
		require.NoError(t, err)
		require.NotEmpty(t, result.Plaintext)
		chan1Data = append(chan1Data, result.Plaintext...)
		bobIndex = bobNextIndex
	}
	require.Equal(t, expectedChan1, chan1Data, "Channel 1 data doesn't match")

	// Bob reads from channel 2 — expects payload2a then payload2b
	expectedChan2 := append(payload2a, payload2b...)
	bobIndex = chan2FirstIndex
	var chan2Data []byte
	chan2Deadline := time.After(reconstructTimeout)
	for len(chan2Data) < len(expectedChan2) {
		select {
		case <-chan2Deadline:
			t.Fatalf("timed out reconstructing channel 2: got %d/%d bytes", len(chan2Data), len(expectedChan2))
		default:
		}
		bobCiphertext, bobEnvDesc, bobEnvHash, bobNextIndex, err := bobThinClient.EncryptRead(chan2ReadCap, bobIndex)
		require.NoError(t, err)
		require.NotNil(t, bobNextIndex)
		bobIndexBytes, err := bobIndex.MarshalBinary()
		require.NoError(t, err)
		result, err := startResending(bobThinClient,
			chan2ReadCap, nil, bobIndexBytes, &replyIndex,
			bobEnvDesc, bobCiphertext, bobEnvHash)
		require.NoError(t, err)
		require.NotEmpty(t, result.Plaintext)
		chan2Data = append(chan2Data, result.Plaintext...)
		bobIndex = bobNextIndex
	}
	require.Equal(t, expectedChan2, chan2Data, "Channel 2 data doesn't match")

}

// TestCreateCourierEnvelopesFromTombstoneRange tests that tombstones can be
// delivered via the copy command using CreateCourierEnvelopesFromTombstoneRange:
// 1. Alice creates a destination channel and a temp copy stream channel
// 2. Alice calls CreateCourierEnvelopesFromTombstoneRange to create N tombstones
// 3. Alice writes the copy stream elements to the temp channel
// 4. Alice sends a Copy command to the courier
// 5. Bob reads from the destination boxes and verifies all return ErrTombstone
func TestCreateCourierEnvelopesFromTombstoneRange(t *testing.T) {
	skipInShortMode(t)
	t.Parallel()
	alice := setupThinClient(t)
	defer alice.Close()
	bob := setupThinClient(t)
	defer bob.Close()

	requireSharedPKIDocument(t, alice, bob)

	// Create destination channel
	destSeed := make([]byte, 32)
	_, err := rand.Reader.Read(destSeed)
	require.NoError(t, err)
	destWriteCap, destReadCap, destFirstIndex, err := alice.NewKeypair(destSeed)
	require.NoError(t, err)

	// Create temp copy stream channel
	tempSeed := make([]byte, 32)
	_, err = rand.Reader.Read(tempSeed)
	require.NoError(t, err)
	tempWriteCap, _, tempFirstIndex, err := alice.NewKeypair(tempSeed)
	require.NoError(t, err)

	// Create tombstone envelopes as copy stream elements
	const numTombstones = 3
	copyStreamChunks, _, nextDestIndex, err := alice.CreateCourierEnvelopesFromTombstoneRange(
		destWriteCap, destFirstIndex, numTombstones, true, true, nil)
	require.NoError(t, err)
	require.NotEmpty(t, copyStreamChunks)
	require.NotNil(t, nextDestIndex)

	// Write copy stream chunks to the temp channel
	tempIndex := tempFirstIndex
	replyIndex := uint8(0)
	for _, chunk := range copyStreamChunks {
		ciphertext, envDesc, envHash, nextTempIndex, err := alice.EncryptWrite(chunk, tempWriteCap, tempIndex)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)
		require.NotNil(t, nextTempIndex)

		_, err = startResending(alice,
			nil, tempWriteCap, nil, &replyIndex,
			envDesc, ciphertext, envHash)
		require.NoError(t, err)

		tempIndex = nextTempIndex
	}

	time.Sleep(30 * time.Second)

	// Send Copy command
	err = alice.StartResendingCopyCommand(tempWriteCap)
	require.NoError(t, err)

	// Bob reads from destination boxes and verifies tombstones
	readIdx := destFirstIndex
	const maxAttempts = 6
	const pollInterval = 10 * time.Second

	for i := 0; i < numTombstones; i++ {
		var tombstoneVerified bool
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			t.Logf("Polling tombstone %d/%d (attempt %d/%d)...", i+1, numTombstones, attempt, maxAttempts)
			time.Sleep(pollInterval)

			ciphertext, envDesc, envHash, nextReadIdx, err := bob.EncryptRead(destReadCap, readIdx)
			require.NoError(t, err)
			require.NotNil(t, nextReadIdx)
			readIdxBytes, err := readIdx.MarshalBinary()
			require.NoError(t, err)

			_, err = startResending(bob,
				destReadCap, nil, readIdxBytes, &replyIndex,
				envDesc, ciphertext, envHash)
			if errors.Is(err, thin.ErrTombstone) {
				tombstoneVerified = true
				break
			}
		}
		require.True(t, tombstoneVerified, "Tombstone %d not propagated after %d attempts", i+1, maxAttempts)

		nextReadIdx, err := bob.NextMessageBoxIndex(readIdx)
		require.NoError(t, err)
		readIdx = nextReadIdx
	}

}

func startResending(c *thin.ThinClient, readCap *bacap.ReadCap, writeCap *bacap.WriteCap, messageBoxIndex []byte, replyIndex *uint8, envelopeDescriptor []byte, messageCiphertext []byte, envelopeHash *[32]byte) (*thin.StartResendingResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), replyWaitTimeout)
	defer cancel()
	return c.StartResendingEncryptedMessageWithContext(ctx, readCap, writeCap, messageBoxIndex, replyIndex, envelopeDescriptor, messageCiphertext, envelopeHash)
}
