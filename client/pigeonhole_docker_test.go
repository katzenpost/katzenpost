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

var threeMessages = [][]byte{
	[]byte("Message 1: The package has been delivered."),
	[]byte("Message 2: Proceed to the safe house."),
	[]byte("Message 3: Mission accomplished."),
}

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
	alice, bob := setupAliceAndBob(t)

	writeCap, readCap, firstIndex := newKeypair(t, alice)
	require.NotNil(t, writeCap, "Alice: WriteCap is nil")
	require.NotNil(t, readCap, "Alice: ReadCap is nil")

	aliceBoxID, err := firstIndex.BoxIDForContext(writeCap.ReadCap(), constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	bobBoxID, err := firstIndex.BoxIDForContext(readCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	require.Equal(t, aliceBoxID.Bytes(), bobBoxID.Bytes(), "Box IDs must match: Alice's write box ID != Bob's read box ID")
	t.Logf("Alice and Bob box ID: %x", aliceBoxID.Bytes())

	// Make message bigger than 29 bytes to ensure courier returns ReplyTypePayload
	// (courier uses >29 byte threshold to distinguish between ACK and Payload replies)
	message := []byte("Bob, the eagle has landed. Rendezvous at dawn. Bring the package and await further instructions.")
	writeResult, _ := writeBox(t, alice, writeCap, firstIndex, message)
	require.Empty(t, writeResult.Plaintext, "Alice: Write operation should return empty plaintext")

	time.Sleep(30 * time.Second)

	readResult, _, err := readBox(t, bob, readCap, firstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, readResult.Plaintext, "Bob: Failed to receive decrypted message")
	require.Equal(t, message, readResult.Plaintext, "Message mismatch: Bob's decrypted message doesn't match Alice's original")
}

// TestNewPigeonholeAPIMultipleMessages tests sending multiple sequential messages
// to verify that state management (PrepareNext/AdvanceState) works correctly
// in the real Docker environment.
func TestNewPigeonholeAPIMultipleMessages(t *testing.T) {
	skipInShortMode(t)
	t.Parallel()
	alice, bob := setupAliceAndBob(t)

	writeCap, readCap, firstIndex := newKeypair(t, alice)
	require.NotNil(t, writeCap, "Alice: WriteCap is nil")
	require.NotNil(t, readCap, "Alice: ReadCap is nil")

	writeIndex, readIndex := firstIndex, firstIndex
	for i, message := range threeMessages {
		var writeResult *thin.StartResendingResult
		writeResult, writeIndex = writeBox(t, alice, writeCap, writeIndex, message)
		require.Empty(t, writeResult.Plaintext, "Alice: Write operation should return empty plaintext")

		time.Sleep(10 * time.Second)

		readResult, next, err := readBox(t, bob, readCap, readIndex)
		require.NoError(t, err)
		require.NotEmpty(t, readResult.Plaintext, "Bob: Failed to receive message %d", i+1)
		require.Equal(t, message, readResult.Plaintext, "Message %d mismatch", i+1)
		readIndex = next
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
	alice, bob := setupAliceAndBob(t)

	writeCap, readCap, firstIndex := newKeypair(t, alice)
	require.NotNil(t, writeCap)
	require.NotNil(t, readCap)

	writeBoxes(t, alice, writeCap, firstIndex, threeMessages)

	time.Sleep(30 * time.Second)

	readIndex := firstIndex
	for i, message := range threeMessages {
		readResult, next, err := readBox(t, bob, readCap, readIndex)
		require.NoError(t, err)
		require.NotEmpty(t, readResult.Plaintext)
		require.Equal(t, message, readResult.Plaintext, "Message %d mismatch", i+1)
		readIndex = next
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
	alice, bob := setupAliceAndBob(t)

	destWriteCap, bobReadCap, destFirstIndex := newKeypair(t, alice)
	require.NotNil(t, destWriteCap, "Destination WriteCap is nil")
	require.NotNil(t, bobReadCap, "Bob ReadCap is nil")

	// Use a 4-byte length prefix so Bob knows when to stop reading
	randomData := make([]byte, 5*1024)
	_, err := rand.Reader.Read(randomData)
	require.NoError(t, err)
	// Length-prefix the payload: [4 bytes length][random data]
	largePayload := make([]byte, 4+len(randomData))
	binary.BigEndian.PutUint32(largePayload[:4], uint32(len(randomData)))
	copy(largePayload[4:], randomData)

	copyStreamChunks, _, err := alice.CreateCourierEnvelopesFromPayload(largePayload, destWriteCap, destFirstIndex, true /* isStart */, true /* isLast */)
	require.NoError(t, err)
	require.NotEmpty(t, copyStreamChunks, "CreateCourierEnvelopesFromPayload returned empty chunks")
	numChunks := len(copyStreamChunks)

	currentDestIndex := destFirstIndex
	for i := 0; i < numChunks; i++ {
		boxID, err := currentDestIndex.BoxIDForContext(bobReadCap, constants.PIGEONHOLE_CTX)
		require.NoError(t, err)
		t.Logf("Chunk %d/%d: Box ID = %x", i+1, numChunks, boxID.Bytes())
		currentDestIndex, err = alice.NextMessageBoxIndex(currentDestIndex)
		require.NoError(t, err)
	}

	require.NoError(t, sendCopyStream(t, alice, copyStreamChunks))

	bobIndex := destFirstIndex
	var reconstructedPayload []byte
	var expectedLength uint32
	for chunkNum := 1; ; chunkNum++ {
		result, next, err := readBox(t, bob, bobReadCap, bobIndex)
		require.NoError(t, err)
		require.NotEmpty(t, result.Plaintext, "Bob: Failed to receive chunk %d", chunkNum)
		reconstructedPayload = append(reconstructedPayload, result.Plaintext...)

		if expectedLength == 0 && len(reconstructedPayload) >= 4 {
			expectedLength = binary.BigEndian.Uint32(reconstructedPayload[:4])
		}
		if expectedLength > 0 && uint32(len(reconstructedPayload)) >= expectedLength+4 {
			break
		}
		bobIndex = next
	}

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
	alice, bob := setupAliceAndBob(t)

	chan1WriteCap, chan1ReadCap, chan1FirstIndex := newKeypair(t, alice)
	require.NotNil(t, chan1WriteCap, "Channel 1 WriteCap is nil")
	require.NotNil(t, chan1ReadCap, "Channel 1 ReadCap is nil")
	chan2WriteCap, chan2ReadCap, chan2FirstIndex := newKeypair(t, alice)
	require.NotNil(t, chan2WriteCap, "Channel 2 WriteCap is nil")
	require.NotNil(t, chan2ReadCap, "Channel 2 ReadCap is nil")

	payload1 := []byte("This is the secret message for Channel 1. It contains important information.")
	payload2 := []byte("This is the confidential data for Channel 2. Handle with care and discretion.")

	chunks1, _, err := alice.CreateCourierEnvelopesFromPayload(payload1, chan1WriteCap, chan1FirstIndex, true, false)
	require.NoError(t, err)
	require.NotEmpty(t, chunks1, "CreateCourierEnvelopesFromPayload returned empty chunks for channel 1")
	chunks2, _, err := alice.CreateCourierEnvelopesFromPayload(payload2, chan2WriteCap, chan2FirstIndex, false, true)
	require.NoError(t, err)
	require.NotEmpty(t, chunks2, "CreateCourierEnvelopesFromPayload returned empty chunks for channel 2")

	require.NoError(t, sendCopyStream(t, alice, append(chunks1, chunks2...)))

	bob1Result, _, err := readBox(t, bob, chan1ReadCap, chan1FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Result.Plaintext, "Bob: Failed to receive data from Channel 1")
	require.Equal(t, payload1, bob1Result.Plaintext, "Channel 1 payload doesn't match")

	bob2Result, _, err := readBox(t, bob, chan2ReadCap, chan2FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Result.Plaintext, "Bob: Failed to receive data from Channel 2")
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
	alice, bob := setupAliceAndBob(t)

	chan1WriteCap, chan1ReadCap, chan1FirstIndex := newKeypair(t, alice)
	require.NotNil(t, chan1WriteCap, "Channel 1 WriteCap is nil")
	require.NotNil(t, chan1ReadCap, "Channel 1 ReadCap is nil")
	chan2WriteCap, chan2ReadCap, chan2FirstIndex := newKeypair(t, alice)
	require.NotNil(t, chan2WriteCap, "Channel 2 WriteCap is nil")
	require.NotNil(t, chan2ReadCap, "Channel 2 ReadCap is nil")

	payload1 := []byte("This is the secret message for Channel 1 using the efficient multi-channel API.")
	payload2 := []byte("This is the confidential data for Channel 2 packed efficiently with payload1.")

	result, err := alice.CreateCourierEnvelopesFromMultiPayload([]thin.DestinationPayload{
		{Payload: payload1, WriteCap: chan1WriteCap, StartIndex: chan1FirstIndex},
		{Payload: payload2, WriteCap: chan2WriteCap, StartIndex: chan2FirstIndex},
	}, true, true, nil)
	require.NoError(t, err)
	require.NotEmpty(t, result.Envelopes, "CreateCourierEnvelopesFromMultiPayload returned empty chunks")

	require.NoError(t, sendCopyStream(t, alice, result.Envelopes))

	bob1Result, _, err := readBox(t, bob, chan1ReadCap, chan1FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob1Result.Plaintext, "Bob: Failed to receive data from Channel 1")
	require.Equal(t, payload1, bob1Result.Plaintext, "Channel 1 payload doesn't match")

	bob2Result, _, err := readBox(t, bob, chan2ReadCap, chan2FirstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bob2Result.Plaintext, "Bob: Failed to receive data from Channel 2")
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

	writeCap, readCap, firstIndex := newKeypair(t, alice)

	message := []byte("Secret message that will be tombstoned")
	writeBox(t, alice, writeCap, firstIndex, message)

	time.Sleep(30 * time.Second)

	readResult, _, err := readBox(t, bob, readCap, firstIndex)
	require.NoError(t, err)
	require.Equal(t, message, readResult.Plaintext)

	tombResult, err := alice.TombstoneRange(writeCap, firstIndex, 1)
	require.NoError(t, err)
	require.Len(t, tombResult.Envelopes, 1)
	tombEnvelope := tombResult.Envelopes[0]
	_, err = startResending(alice, nil, writeCap, nil, nil, tombEnvelope.EnvelopeDescriptor, tombEnvelope.MessageCiphertext, tombEnvelope.EnvelopeHash)
	require.NoError(t, err)

	requireTombstone(t, bob, readCap, firstIndex, 1)
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

	writeCap, readCap, firstIndex := newKeypair(t, alice)

	const numMessages = 3
	messages := [][]byte{
		[]byte("Message 1 - will be tombstoned"),
		[]byte("Message 2 - will be tombstoned"),
		[]byte("Message 3 - will be tombstoned"),
	}
	writeBoxes(t, alice, writeCap, firstIndex, messages)

	time.Sleep(30 * time.Second)

	readIdx := firstIndex
	for _, expectedMsg := range messages {
		readResult, next, err := readBox(t, bob, readCap, readIdx)
		require.NoError(t, err)
		require.Equal(t, expectedMsg, readResult.Plaintext)
		readIdx = next
	}

	result, err := alice.TombstoneRange(writeCap, firstIndex, numMessages)
	require.NoError(t, err)
	require.Len(t, result.Envelopes, numMessages)

	for _, envelope := range result.Envelopes {
		_, err = startResending(alice,
			nil, writeCap, nil, nil,
			envelope.EnvelopeDescriptor, envelope.MessageCiphertext, envelope.EnvelopeHash,
		)
		require.NoError(t, err)
	}

	time.Sleep(60 * time.Second)

	readIdx = firstIndex
	for i := 0; i < numMessages; i++ {
		_, next, err := readBox(t, bob, readCap, readIdx)
		require.True(t, errors.Is(err, thin.ErrTombstone), "Expected ErrTombstone for box %d, got: %v", i+1, err)
		readIdx = next
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
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	validatePKIDocument(t, bobThinClient)

	_, readCap, firstIndex := newKeypair(t, bobThinClient)
	require.NotNil(t, readCap, "ReadCap should not be nil")

	bobCiphertext, bobEnvDesc, bobEnvHash, _, err := bobThinClient.EncryptRead(readCap, firstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, bobCiphertext, "EncryptRead should return ciphertext")
	firstIndexBytes, err := firstIndex.MarshalBinary()
	require.NoError(t, err)

	// Use StartResendingEncryptedMessageNoRetry to get immediate error without retries
	replyIndex := uint8(0)
	_, err = bobThinClient.StartResendingEncryptedMessageNoRetry(
		readCap, nil, firstIndexBytes, &replyIndex,
		bobEnvDesc, bobCiphertext, bobEnvHash)

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
	aliceThinClient, bobThinClient := setupAliceAndBob(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	aliceWriteCap, bobReadCap, firstIndex := newKeypair(t, aliceThinClient)
	require.NotNil(t, aliceWriteCap, "Alice: WriteCap is nil")
	require.NotNil(t, bobReadCap, "Bob: ReadCap is nil")

	boxID, err := firstIndex.BoxIDForContext(bobReadCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	t.Logf("Shared Box ID: %x", boxID.Bytes())

	type readResult struct {
		plaintext []byte
		err       error
	}
	bobResultChan := make(chan readResult, 1)

	go func() {
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

		// The read will fail initially with BoxIDNotFound, but kpclientd will retry
		replyIndex := uint8(0)
		result, err := startResending(bobThinClient,
			bobReadCap, nil, firstIndexBytes, &replyIndex,
			bobEnvDesc, bobCiphertext, bobEnvHash)
		var pt []byte
		if result != nil {
			pt = result.Plaintext
		}
		bobResultChan <- readResult{pt, err}
	}()

	time.Sleep(5 * time.Second)

	aliceMessage := []byte("Hello Bob! I wrote this after you started reading.")
	writeBox(t, aliceThinClient, aliceWriteCap, firstIndex, aliceMessage)

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
	thinClient := setupThinClient(t)
	defer thinClient.Close()

	validatePKIDocument(t, thinClient)

	writeCap, _, firstIndex := newKeypair(t, thinClient)
	require.NotNil(t, writeCap, "WriteCap should not be nil")

	message1 := []byte("First message - this should work")
	ciphertext1, envDesc1, envHash1, _, err := thinClient.EncryptWrite(message1, writeCap, firstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext1, "EncryptWrite should return ciphertext")

	_, err = startResending(thinClient, nil, writeCap, nil, nil, envDesc1, ciphertext1, envHash1)
	require.NoError(t, err, "First write should succeed")

	time.Sleep(5 * time.Second)

	message2 := []byte("Second message - this should fail")
	ciphertext2, envDesc2, envHash2, _, err := thinClient.EncryptWrite(message2, writeCap, firstIndex)
	require.NoError(t, err, "EncryptWrite should succeed even for duplicate")

	// Use StartResendingEncryptedMessageReturnBoxExists to get the error instead of
	// treating it as idempotent success
	_, err = thinClient.StartResendingEncryptedMessageReturnBoxExists(nil, writeCap, nil, nil, envDesc2, ciphertext2, envHash2)

	require.Error(t, err, "Expected an error when writing to existing box")
	require.ErrorIs(t, err, thin.ErrBoxAlreadyExists, "Expected ErrBoxAlreadyExists error, got: %v", err)
}

func TestCopyOntoAlreadyExistingBoxError(t *testing.T) {
	skipInShortMode(t)
	t.Parallel()
	thinClient := setupThinClient(t)
	defer thinClient.Close()

	validatePKIDocument(t, thinClient)

	writeCap, _, firstIndex := newKeypair(t, thinClient)
	require.NotNil(t, writeCap, "WriteCap should not be nil")

	message1 := []byte("First message - this should work")
	ciphertext1, envDesc1, envHash1, _, err := thinClient.EncryptWrite(message1, writeCap, firstIndex)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext1, "EncryptWrite should return ciphertext")

	_, err = startResending(thinClient, nil, writeCap, nil, nil, envDesc1, ciphertext1, envHash1)
	require.NoError(t, err, "First write should succeed")

	time.Sleep(5 * time.Second)

	largePayload := make([]byte, 2000)
	_, err = rand.Reader.Read(largePayload)
	require.NoError(t, err)

	copyStreamChunks, _, err := thinClient.CreateCourierEnvelopesFromPayload(largePayload, writeCap, firstIndex, true /* isStart */, true /* isLast */)
	require.NoError(t, err)
	require.NotEmpty(t, copyStreamChunks, "CreateCourierEnvelopesFromPayload returned empty chunks")

	require.Error(t, sendCopyStream(t, thinClient, copyStreamChunks))
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
	alice, bob := setupAliceAndBob(t)

	destWriteCap, bobReadCap, destFirstIndex := newKeypair(t, alice)

	// Use pigeonhole geometry to size the payload: 3x the max box payload
	// so each chunk fills exactly one destination box.
	chunkSize := alice.GetPigeonholeGeometry().MaxPlaintextPayloadLength
	t.Logf("MaxPlaintextPayloadLength = %d bytes", chunkSize)
	fullPayload := make([]byte, 3*chunkSize)
	_, err := rand.Reader.Read(fullPayload)
	require.NoError(t, err)

	envelopes1, nextDest1, err := alice.CreateCourierEnvelopesFromPayload(
		fullPayload[:chunkSize], destWriteCap, destFirstIndex, true, false)
	require.NoError(t, err)
	require.NotEmpty(t, envelopes1)
	require.NotNil(t, nextDest1)

	envelopes2, nextDest2, err := alice.CreateCourierEnvelopesFromPayload(
		fullPayload[chunkSize:2*chunkSize], destWriteCap, nextDest1, false, false)
	require.NoError(t, err)
	require.NotEmpty(t, envelopes2)
	require.NotNil(t, nextDest2)

	envelopes3, nextDest3, err := alice.CreateCourierEnvelopesFromPayload(
		fullPayload[2*chunkSize:], destWriteCap, nextDest2, false, true)
	require.NoError(t, err)
	require.NotEmpty(t, envelopes3)
	require.NotNil(t, nextDest3)

	allTempElements := append(append(envelopes1, envelopes2...), envelopes3...)
	require.NoError(t, sendCopyStream(t, alice, allTempElements))

	reconstructed := readStream(t, bob, bobReadCap, destFirstIndex, len(fullPayload))
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
	alice, bob := setupAliceAndBob(t)

	chan1WriteCap, chan1ReadCap, chan1FirstIndex := newKeypair(t, alice)
	chan2WriteCap, chan2ReadCap, chan2FirstIndex := newKeypair(t, alice)

	// Use pigeonhole geometry to size payloads: each payload is exactly one box payload
	// so each call writes one destination box per channel.
	maxPayload := alice.GetPigeonholeGeometry().MaxPlaintextPayloadLength
	t.Logf("MaxPlaintextPayloadLength = %d bytes", maxPayload)

	payloads := make([][]byte, 4)
	for i := range payloads {
		payloads[i] = make([]byte, maxPayload)
		_, err := rand.Reader.Read(payloads[i])
		require.NoError(t, err)
	}
	payload1a, payload2a, payload1b, payload2b := payloads[0], payloads[1], payloads[2], payloads[3]

	result1, err := alice.CreateCourierEnvelopesFromMultiPayload([]thin.DestinationPayload{
		{Payload: payload1a, WriteCap: chan1WriteCap, StartIndex: chan1FirstIndex},
		{Payload: payload2a, WriteCap: chan2WriteCap, StartIndex: chan2FirstIndex},
	}, true, false, nil)
	require.NoError(t, err)
	require.NotEmpty(t, result1.Envelopes)
	require.Len(t, result1.NextDestIndices, 2)

	result2, err := alice.CreateCourierEnvelopesFromMultiPayload([]thin.DestinationPayload{
		{Payload: payload1b, WriteCap: chan1WriteCap, StartIndex: result1.NextDestIndices[0]},
		{Payload: payload2b, WriteCap: chan2WriteCap, StartIndex: result1.NextDestIndices[1]},
	}, false, true, result1.Buffer)
	require.NoError(t, err)
	require.NotEmpty(t, result2.Envelopes)
	require.Len(t, result2.NextDestIndices, 2)

	require.NoError(t, sendCopyStream(t, alice, append(result1.Envelopes, result2.Envelopes...)))

	expectedChan1 := append(payload1a, payload1b...)
	chan1Data := readStream(t, bob, chan1ReadCap, chan1FirstIndex, len(expectedChan1))
	require.Equal(t, expectedChan1, chan1Data, "Channel 1 data doesn't match")

	expectedChan2 := append(payload2a, payload2b...)
	chan2Data := readStream(t, bob, chan2ReadCap, chan2FirstIndex, len(expectedChan2))
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
	alice, bob := setupAliceAndBob(t)

	destWriteCap, destReadCap, destFirstIndex := newKeypair(t, alice)

	const numTombstones = 3
	copyStreamChunks, _, nextDestIndex, err := alice.CreateCourierEnvelopesFromTombstoneRange(
		destWriteCap, destFirstIndex, numTombstones, true, true, nil)
	require.NoError(t, err)
	require.NotEmpty(t, copyStreamChunks)
	require.NotNil(t, nextDestIndex)

	require.NoError(t, sendCopyStream(t, alice, copyStreamChunks))

	readIdx := destFirstIndex
	for i := 0; i < numTombstones; i++ {
		requireTombstone(t, bob, destReadCap, readIdx, i+1)
		readIdx, err = bob.NextMessageBoxIndex(readIdx)
		require.NoError(t, err)
	}
}

func setupAliceAndBob(t *testing.T) (*thin.ThinClient, *thin.ThinClient) {
	t.Helper()
	alice := setupThinClient(t)
	t.Cleanup(func() { alice.Close() })
	bob := setupThinClient(t)
	t.Cleanup(func() { bob.Close() })
	requireSharedPKIDocument(t, alice, bob)
	return alice, bob
}

func newKeypair(t *testing.T, c *thin.ThinClient) (*bacap.WriteCap, *bacap.ReadCap, *bacap.MessageBoxIndex) {
	t.Helper()
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)
	writeCap, readCap, firstIndex, err := c.NewKeypair(seed)
	require.NoError(t, err)
	return writeCap, readCap, firstIndex
}

func writeBox(t *testing.T, c *thin.ThinClient, writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex, plaintext []byte) (*thin.StartResendingResult, *bacap.MessageBoxIndex) {
	t.Helper()
	ciphertext, envDesc, envHash, next, err := c.EncryptWrite(plaintext, writeCap, idx)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext, "EncryptWrite returned empty ciphertext")
	require.NotNil(t, next)
	replyIndex := uint8(0)
	result, err := startResending(c, nil, writeCap, nil, &replyIndex, envDesc, ciphertext, envHash)
	require.NoError(t, err)
	return result, next
}

func writeBoxes(t *testing.T, c *thin.ThinClient, writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex, plaintexts [][]byte) {
	t.Helper()
	for _, plaintext := range plaintexts {
		_, idx = writeBox(t, c, writeCap, idx, plaintext)
	}
}

func readBox(t *testing.T, c *thin.ThinClient, readCap *bacap.ReadCap, idx *bacap.MessageBoxIndex) (*thin.StartResendingResult, *bacap.MessageBoxIndex, error) {
	t.Helper()
	ciphertext, envDesc, envHash, next, err := c.EncryptRead(readCap, idx)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext, "EncryptRead returned empty ciphertext")
	require.NotNil(t, next)
	idxBytes, err := idx.MarshalBinary()
	require.NoError(t, err)
	replyIndex := uint8(0)
	result, err := startResending(c, readCap, nil, idxBytes, &replyIndex, envDesc, ciphertext, envHash)
	return result, next, err
}

func readStream(t *testing.T, c *thin.ThinClient, readCap *bacap.ReadCap, idx *bacap.MessageBoxIndex, n int) []byte {
	t.Helper()
	var data []byte
	deadline := time.After(reconstructTimeout)
	for len(data) < n {
		select {
		case <-deadline:
			t.Fatalf("timed out reconstructing payload: got %d/%d bytes", len(data), n)
		default:
		}
		result, next, err := readBox(t, c, readCap, idx)
		require.NoError(t, err)
		require.NotEmpty(t, result.Plaintext)
		data = append(data, result.Plaintext...)
		idx = next
	}
	return data
}

func sendCopyStream(t *testing.T, c *thin.ThinClient, chunks [][]byte) error {
	t.Helper()
	tempWriteCap, _, tempFirstIndex := newKeypair(t, c)
	require.NotNil(t, tempWriteCap, "Temp WriteCap is nil")
	writeBoxes(t, c, tempWriteCap, tempFirstIndex, chunks)
	time.Sleep(30 * time.Second)
	return c.StartResendingCopyCommand(tempWriteCap)
}

func requireTombstone(t *testing.T, c *thin.ThinClient, readCap *bacap.ReadCap, idx *bacap.MessageBoxIndex, box int) {
	t.Helper()
	const maxAttempts = 6
	verified := false
	for attempt := 1; attempt <= maxAttempts && !verified; attempt++ {
		t.Logf("Polling tombstone %d (attempt %d/%d)", box, attempt, maxAttempts)
		time.Sleep(10 * time.Second)
		_, _, err := readBox(t, c, readCap, idx)
		verified = errors.Is(err, thin.ErrTombstone)
	}
	require.True(t, verified, "Tombstone %d not propagated after %d attempts", box, maxAttempts)
}

func startResending(c *thin.ThinClient, readCap *bacap.ReadCap, writeCap *bacap.WriteCap, messageBoxIndex []byte, replyIndex *uint8, envelopeDescriptor []byte, messageCiphertext []byte, envelopeHash *[32]byte) (*thin.StartResendingResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), replyWaitTimeout)
	defer cancel()
	return c.StartResendingEncryptedMessageWithContext(ctx, readCap, writeCap, messageBoxIndex, replyIndex, envelopeDescriptor, messageCiphertext, envelopeHash)
}
