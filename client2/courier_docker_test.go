//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

func TestDockerCourierServiceNewThinclientAPI(t *testing.T) {
	t.Log("TESTING COURIER SERVICE - New thin client API")

	// Setup clients and get current epoch
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	currentDoc := validatePKIDocument(t, aliceThinClient)
	currentEpoch := currentDoc.Epoch
	bobDoc := validatePKIDocument(t, bobThinClient)
	require.Equal(t, currentEpoch, bobDoc.Epoch, "Alice and Bob must use same PKI epoch")
	t.Logf("Using PKI document for epoch %d", currentEpoch)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Alice creates write channel
	t.Log("Alice: Creating write channel")
	channelID, readCap, _, _, err := aliceThinClient.CreateWriteChannel(ctx, nil, nil)
	require.NoError(t, err)
	t.Logf("Alice: Created write channel %d", channelID)

	// Bob creates read channel
	t.Log("Bob: Creating read channel")
	bobChannelID, _, err := bobThinClient.CreateReadChannelV2(ctx, readCap, nil)
	require.NoError(t, err)
	t.Logf("Bob: Created read channel %d", bobChannelID)

	// Alice writes message
	originalMessage := []byte("Hello from Alice to Bob via new channel API!")
	t.Log("Alice: Writing message")
	writePayload, _, err := aliceThinClient.WriteChannelV2(ctx, channelID, originalMessage)
	require.NoError(t, err)
	require.NotNil(t, writePayload)
	t.Logf("Alice: Generated write payload (%d bytes)", len(writePayload))

	// Alice sends write query via courier
	epochDoc, err := aliceThinClient.PKIDocumentForEpoch(currentEpoch)
	require.NoError(t, err)
	courierServices := common.FindServices("courier", epochDoc)
	require.True(t, len(courierServices) > 0, "No courier services found")
	courierService := courierServices[0]

	identityHash := hash.Sum256(courierService.MixDescriptor.IdentityKey)
	err = aliceThinClient.SendChannelQuery(ctx, channelID, writePayload, &identityHash, courierService.RecipientQueueID)
	require.NoError(t, err)
	t.Log("Alice: Sent write query to courier")

	// Wait for message propagation
	time.Sleep(3 * time.Second)

	// Bob reads message
	t.Log("Bob: Reading message")
	messageID := bobThinClient.NewMessageID()
	readPayload, _, err := bobThinClient.ReadChannelV2(ctx, bobChannelID, messageID)
	require.NoError(t, err)
	require.NotNil(t, readPayload)
	t.Logf("Bob: Generated read payload (%d bytes)", len(readPayload))

	// Bob sends read query via courier
	err = bobThinClient.SendChannelQuery(ctx, bobChannelID, readPayload, &identityHash, courierService.RecipientQueueID)
	require.NoError(t, err)
	t.Log("Bob: Sent read query to courier")

	// Wait for Bob to receive Alice's message via MessageReplyEvent with retry mechanism
	t.Log("Bob: Waiting for message reply...")
	eventSink := bobThinClient.EventSink()
	defer bobThinClient.StopEventSink(eventSink)

	var receivedPayload []byte
	maxRetries := 10
	retryDelay := 2 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		t.Logf("Bob: Waiting for message reply (attempt %d/%d)...", attempt, maxRetries)

		timeout := time.After(10 * time.Second)

		for {
			select {
			case <-timeout:
				if attempt == maxRetries {
					t.Fatal("Timeout waiting for message reply after all retries")
				}
				t.Logf("Bob: Timeout on attempt %d, retrying...", attempt)
				goto nextAttempt
			case event := <-eventSink:
				switch v := event.(type) {
				case *thin.MessageReplyEvent:
					if v.Err != nil {
						t.Fatalf("Bob: Message reply error: %v", v.Err)
					}
					receivedPayload = v.Payload
					t.Logf("Bob: Received message reply (%d bytes)", len(receivedPayload))

					// Check if we got actual data or empty payload
					if len(receivedPayload) > 0 {
						t.Logf("Bob: Successfully received message on attempt %d", attempt)
						goto messageReceived
					} else {
						t.Logf("Bob: Received empty payload on attempt %d, retrying...", attempt)
						goto nextAttempt
					}
				case *thin.ConnectionStatusEvent:
					if !v.IsConnected {
						t.Fatal("Bob: Lost connection while waiting for reply")
					}
				default:
					// Ignore other events
				}
			}
		}

	nextAttempt:
		if attempt < maxRetries {
			t.Logf("Bob: Waiting %v before retry...", retryDelay)
			time.Sleep(retryDelay)

			// Send another read query for retry
			readPayload, _, err := bobThinClient.ReadChannelV2(ctx, bobChannelID, messageID)
			require.NoError(t, err)
			err = bobThinClient.SendChannelQuery(ctx, bobChannelID, readPayload, &identityHash, courierService.RecipientQueueID)
			require.NoError(t, err)
			t.Logf("Bob: Sent retry read query (attempt %d)", attempt+1)
		}
	}

messageReceived:
	// Debug: examine the payload structure
	t.Logf("Bob: Received payload (%d bytes)", len(receivedPayload))
	t.Logf("Bob: First 64 bytes: %x", receivedPayload[:min(64, len(receivedPayload))])

	// Try extracting directly as padded payload (like reference implementation)
	actualMessage, err := pigeonhole.ExtractMessageFromPaddedPayload(receivedPayload)
	if err == nil {
		// Direct extraction worked
		require.True(t, bytes.Equal(originalMessage, actualMessage),
			"Bob's received message does not match Alice's original message")
		t.Log("SUCCESS: Bob received Alice's exact original message!")
		t.Logf("Original: %s", string(originalMessage))
		t.Logf("Received: %s", string(actualMessage))
		return
	}

	t.Logf("Bob: Direct extraction failed: %v", err)
	t.Logf("Bob: Trying to parse as protocol structures...")

	// If direct extraction fails, the payload might be wrapped in protocol structures
	// Let's examine the payload more carefully
	if len(receivedPayload) >= 4 {
		// Check if it starts with a length prefix
		length := binary.BigEndian.Uint32(receivedPayload[:4])
		t.Logf("Bob: Potential length prefix: %d (0x%x)", length, length)

		if length > 0 && length < uint32(len(receivedPayload)) {
			// Try extracting from offset 4
			actualMessage, err := pigeonhole.ExtractMessageFromPaddedPayload(receivedPayload[4:])
			if err == nil {
				require.True(t, bytes.Equal(originalMessage, actualMessage),
					"Bob's received message does not match Alice's original message")
				t.Log("SUCCESS: Bob received Alice's message after skipping length prefix!")
				t.Logf("Original: %s", string(originalMessage))
				t.Logf("Received: %s", string(actualMessage))
				return
			}
			t.Logf("Bob: Extraction after length prefix failed: %v", err)
		}
	}

	t.Fatalf("Bob: Could not extract message from received payload")
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

	// Wait for PKI document (both clients should have it) and ensure same epoch
	aliceDoc := validatePKIDocument(t, aliceThinClient)
	bobDoc := validatePKIDocument(t, bobThinClient)
	currentEpoch := aliceDoc.Epoch
	require.Equal(t, currentEpoch, bobDoc.Epoch, "Alice and Bob should use the same PKI epoch")
	t.Logf("Both clients using PKI document for epoch %d", currentEpoch)

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
