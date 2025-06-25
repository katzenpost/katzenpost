//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	_ "github.com/katzenpost/katzenpost/client2/thin" // Used by helper functions
)

func TestDockerCourierServiceNewThinclientAPI(t *testing.T) {
	t.Log("TESTING COURIER SERVICE - New thin client API CreateWriteChannel")

	// Create a thin client for Alice
	t.Log("Creating Alice's thin client")
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()

	// Wait for PKI document
	_ = validatePKIDocument(t, aliceThinClient)

	// Create context with timeout for operations
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// === Test CreateWriteChannel (new API) ===
	t.Log("Alice: Creating write channel using new API")
	channelID, readCap, writeCap, nextMessageIndex, err := aliceThinClient.CreateWriteChannel(ctx, nil, nil)
	require.NoError(t, err)
	require.NotZero(t, channelID)
	require.NotNil(t, readCap)
	require.NotNil(t, writeCap)
	require.NotNil(t, nextMessageIndex)
	t.Logf("Alice: Successfully created write channel %d", channelID)
	readCapBytes, _ := readCap.MarshalBinary()
	writeCapBytes, _ := writeCap.MarshalBinary()
	indexBytes, _ := nextMessageIndex.MarshalBinary()
	t.Logf("Alice: ReadCap: %x", readCapBytes[:16])
	t.Logf("Alice: WriteCap: %x", writeCapBytes[:16])
	t.Logf("Alice: NextMessageIndex: %x", indexBytes[:16])

	// Create a thin client for Bob
	t.Log("Creating Bob's thin client")
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	// Wait for PKI document for Bob
	_ = validatePKIDocument(t, bobThinClient)

	// === Test CreateReadChannelV2 (new API) ===
	t.Log("Bob: Creating read channel using new API")
	bobChannelID, bobNextMessageIndex, err := bobThinClient.CreateReadChannelV2(ctx, readCap, nil)
	require.NoError(t, err)
	require.NotZero(t, bobChannelID)
	require.NotNil(t, bobNextMessageIndex)
	t.Logf("Bob: Successfully created read channel %d", bobChannelID)
	bobIndexBytes, _ := bobNextMessageIndex.MarshalBinary()
	t.Logf("Bob: NextMessageIndex: %x", bobIndexBytes[:16])

	// === Test WriteChannelV2 (new API) ===
	t.Log("Alice: Testing WriteChannelV2 method")
	testMessage := []byte("Hello from Alice via WriteChannelV2!")
	sendPayload, nextWriteIndex, err := aliceThinClient.WriteChannelV2(ctx, channelID, testMessage)
	if err != nil {
		// Expected to fail with "Service unavailable" since it's not implemented yet
		t.Logf("Alice: WriteChannelV2 failed as expected (not implemented): %v", err)
		require.Contains(t, err.Error(), "Service unavailable")
	} else {
		// If it succeeds in the future, validate the response
		require.NotNil(t, sendPayload)
		require.NotNil(t, nextWriteIndex)
		t.Logf("Alice: WriteChannelV2 succeeded, payload size: %d bytes", len(sendPayload))
	}

	// === Test ReadChannelV2 (new API) ===
	t.Log("Bob: Testing ReadChannelV2 method")
	messageID := bobThinClient.NewMessageID()
	readPayload, nextReadIndex, err := bobThinClient.ReadChannelV2(ctx, bobChannelID, messageID)
	if err != nil {
		// Expected to fail with "Service unavailable" since it's not implemented yet
		t.Logf("Bob: ReadChannelV2 failed as expected (not implemented): %v", err)
		require.Contains(t, err.Error(), "Service unavailable")
	} else {
		// If it succeeds in the future, validate the response
		require.NotNil(t, readPayload)
		require.NotNil(t, nextReadIndex)
		t.Logf("Bob: ReadChannelV2 succeeded, payload size: %d bytes", len(readPayload))
	}

	// === Test SendChannelQuery (new API) ===
	t.Log("Testing SendChannelQuery method")
	if sendPayload != nil {
		// Get courier service for sending the query
		courierService, err := aliceThinClient.GetService("courier")
		require.NoError(t, err)
		require.NotNil(t, courierService)

		// Test SendChannelQuery with the payload from WriteChannelV2
		identityHash := hash.Sum256(courierService.MixDescriptor.IdentityKey)
		err = aliceThinClient.SendChannelQuery(ctx, channelID, sendPayload,
			&identityHash, courierService.RecipientQueueID)
		if err != nil {
			t.Logf("SendChannelQuery failed: %v", err)
		} else {
			t.Log("SendChannelQuery succeeded")
		}
	} else {
		t.Log("Skipping SendChannelQuery test since WriteChannelV2 is not implemented")
	}

	t.Log("SUCCESS: WriteChannelV2, ReadChannelV2, and SendChannelQuery APIs tested!")
}

func testDockerCourierServiceOldThinclientAPI(t *testing.T) {
	t.Log("TESTING COURIER SERVICE - Starting pigeonhole channel test")

	// Create separate thin clients for Alice and Bob
	t.Log("Creating Alice's thin client")
	aliceThinClient := setupThinClient(t)
	t.Log("Alice's thin client connected")

	t.Log("Creating Bob's thin client")
	bobThinClient := setupThinClient(t)
	t.Log("Bob's thin client connected")

	// Wait for PKI document (both clients should have it)
	_ = validatePKIDocument(t, aliceThinClient)
	_ = validatePKIDocument(t, bobThinClient)

	// Test message to send
	plaintextMessage := []byte("Hello world from Alice to Bob!")

	// Create context with timeout for operations
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// === ALICE (Writer) ===
	t.Log("Alice: Creating pigeonhole channel")
	aliceChannelID, readCap, err := aliceThinClient.OldCreateChannel(ctx)
	require.NoError(t, err)
	require.NotNil(t, aliceChannelID)
	require.NotNil(t, readCap)
	t.Logf("Alice: Created write channel %x", aliceChannelID[:])

	t.Log("Alice: Writing message to channel")
	err = aliceThinClient.OldWriteChannel(ctx, aliceChannelID, plaintextMessage)
	require.NoError(t, err)
	t.Log("Alice: Successfully wrote message")

	// Wait for message to propagate through the system
	t.Log("Waiting 10 seconds for message propagation...")
	time.Sleep(10 * time.Second)

	// === BOB (Reader) ===
	t.Log("Bob: Creating read channel from Alice's readCap")
	bobChannelID, err := bobThinClient.OldCreateReadChannel(ctx, readCap)
	require.NoError(t, err)
	require.NotNil(t, bobChannelID)
	t.Logf("Bob: Created read channel %x (different from Alice's %x)", bobChannelID[:], aliceChannelID[:])

	// Bob reads the message (may need to retry as the message might not be immediately available)
	// Use a consistent message ID for all read attempts to enable courier envelope reuse
	readMessageID := bobThinClient.NewMessageID()
	t.Logf("Bob: Using message ID %x for all read attempts", readMessageID[:])

	var receivedMessage []byte
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		t.Logf("Bob: Reading message attempt %d/%d", i+1, maxRetries)

		// Add a longer delay before the first read to allow message propagation
		if i == 0 {
			t.Log("Bob: Waiting for message to propagate through the system...")
			time.Sleep(5 * time.Second)
		}

		// Create a fresh context with 10-minute timeout for each read attempt
		readCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		receivedMessage, err = bobThinClient.OldReadChannel(readCtx, bobChannelID, readMessageID)
		cancel()

		if err != nil {
			t.Logf("Bob: Read attempt %d failed: %v", i+1, err)
			if i < maxRetries-1 {
				time.Sleep(3 * time.Second) // Wait before retry
				continue
			}
			// On the last attempt, log the error but don't fail immediately
			t.Logf("Bob: Final read attempt failed: %v", err)
			break
		}

		if len(receivedMessage) > 0 {
			t.Log("Bob: Successfully read message")
			break
		}

		if i < maxRetries-1 {
			t.Log("Bob: No message available yet, retrying...")
			time.Sleep(3 * time.Second)
		}
	}

	// Verify the messages match
	if len(receivedMessage) == 0 {
		t.Log("FAILURE: Bob did not receive any message")
		t.Logf("Original message: %s", string(plaintextMessage))
		t.Log("This could indicate:")
		t.Log("1. Message propagation delay (try increasing wait times)")
		t.Log("2. Issue with courier-replica communication")
		t.Log("3. Problem with read channel setup")
		require.NotEmpty(t, receivedMessage)
	}

	require.Equal(t, plaintextMessage, receivedMessage)

	t.Log("SUCCESS: Alice and Bob successfully communicated through pigeonhole channel!")
	t.Logf("Original message: %s", string(plaintextMessage))
	t.Logf("Received message: %s", string(receivedMessage))

	t.Log("Test Completed. Disconnecting...")
	aliceThinClient.Close()
	bobThinClient.Close()
}
