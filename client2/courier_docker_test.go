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
	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/thin"
)

// sendQueryAndWait sends a channel query and waits for the reply with retry logic
func sendQueryAndWait(t *testing.T, client *thin.ThinClient, channelID uint16, message []byte, nodeID *[32]byte, queueID []byte) []byte {
	maxRetries := 5
	retryDelay := 3 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		t.Logf("Sending channel query (attempt %d/%d)", attempt, maxRetries)

		eventSink := client.EventSink()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		err := client.SendChannelQuery(ctx, channelID, message, nodeID, queueID)
		require.NoError(t, err)

		// Wait for reply
		timeout := time.After(15 * time.Second)
		for {
			select {
			case <-timeout:
				t.Logf("Timeout on attempt %d", attempt)
				cancel()
				client.StopEventSink(eventSink)
				goto nextAttempt
			case <-ctx.Done():
				t.Logf("Context cancelled on attempt %d", attempt)
				cancel()
				client.StopEventSink(eventSink)
				goto nextAttempt
			case event := <-eventSink:
				switch v := event.(type) {
				case *thin.MessageIDGarbageCollected:
					t.Log("MessageIDGarbageCollected")
				case *thin.ConnectionStatusEvent:
					t.Log("ConnectionStatusEvent")
					if !v.IsConnected {
						t.Fatal("socket connection lost")
					}
				case *thin.NewDocumentEvent:
					t.Log("NewPKIDocumentEvent")
				case *thin.MessageSentEvent:
					t.Log("MessageSentEvent")
				case *thin.MessageReplyEvent:
					t.Log("MessageReplyEvent")
					if v.Err != nil {
						t.Logf("Message reply error on attempt %d: %v", attempt, v.Err)
						cancel()
						client.StopEventSink(eventSink)
						goto nextAttempt
					}
					if v.Payload != nil && len(v.Payload) > 0 {
						t.Logf("SUCCESS: Received non-empty payload on attempt %d (%d bytes)", attempt, len(v.Payload))
						cancel()
						client.StopEventSink(eventSink)
						return v.Payload
					} else {
						t.Logf("Received nil/empty payload on attempt %d, retrying...", attempt)
						cancel()
						client.StopEventSink(eventSink)
						goto nextAttempt
					}
				default:
					t.Logf("Ignoring event type: %T", event)
				}
			}
		}

	nextAttempt:
		if attempt < maxRetries {
			t.Logf("Waiting %v before retry...", retryDelay)
			time.Sleep(retryDelay)
		}
	}

	t.Fatalf("Failed to receive valid payload after %d attempts", maxRetries)
	return nil
}

func TestDockerCourierServiceNewThinclientAPI(t *testing.T) {
	t.Log("TESTING COURIER SERVICE - New thin client API")
	// NOTE: The new API automatically extracts messages from padded payloads in the daemon,
	// so clients receive the original message directly, not the raw padded payload.

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

	// Bob reads message using the helper function
	t.Log("Bob: Reading message")
	messageID := bobThinClient.NewMessageID()
	readPayload, _, err := bobThinClient.ReadChannelV2(ctx, bobChannelID, messageID)
	require.NoError(t, err)
	require.NotNil(t, readPayload)
	t.Logf("Bob: Generated read payload (%d bytes)", len(readPayload))

	// Bob sends read query and waits for reply using helper
	t.Log("Bob: Sending read query and waiting for reply...")
	receivedPayload := sendQueryAndWait(t, bobThinClient, bobChannelID, readPayload, &identityHash, courierService.RecipientQueueID)
	require.NotNil(t, receivedPayload, "Bob: Received nil payload")

	require.Equal(t, originalMessage, receivedPayload, "Bob should receive the original message")
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
