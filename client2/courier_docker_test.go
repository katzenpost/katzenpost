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
