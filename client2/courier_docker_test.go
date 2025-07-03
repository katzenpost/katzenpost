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

// attemptResult represents the result of a single query attempt
type attemptResult struct {
	payload []byte
	retry   bool
	success bool
}

// cleanupAttempt handles cleanup for a failed attempt
func cleanupAttempt(t *testing.T, cancel context.CancelFunc, client *thin.ThinClient, eventSink chan thin.Event, attempt int, reason string) {
	t.Logf("%s on attempt %d", reason, attempt)
	cancel()
	client.StopEventSink(eventSink)
}

// handleMessageReplyEvent processes MessageReplyEvent and returns the result
func handleMessageReplyEvent(t *testing.T, v *thin.MessageReplyEvent, attempt int) attemptResult {
	t.Log("MessageReplyEvent")

	if v.Err != "" {
		t.Logf("Message reply error on attempt %d: %v", attempt, v.Err)
		return attemptResult{retry: true}
	}

	if v.Payload != nil && len(v.Payload) > 0 {
		t.Logf("SUCCESS: Received non-empty payload on attempt %d (%d bytes)", attempt, len(v.Payload))
		return attemptResult{payload: v.Payload, success: true}
	}

	t.Logf("Received nil/empty payload on attempt %d, retrying...", attempt)
	return attemptResult{retry: true}
}

// handleEvent processes a single event and returns the result
func handleEvent(t *testing.T, event thin.Event, attempt int) attemptResult {
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
		return handleMessageReplyEvent(t, v, attempt)
	default:
		t.Logf("Ignoring event type: %T", event)
	}
	return attemptResult{} // Continue waiting
}

// waitForReply waits for a reply from the event sink
func waitForReply(t *testing.T, client *thin.ThinClient, eventSink chan thin.Event, ctx context.Context, cancel context.CancelFunc, attempt int) attemptResult {
	timeout := time.After(15 * time.Second)

	for {
		select {
		case <-timeout:
			cleanupAttempt(t, cancel, client, eventSink, attempt, "Timeout")
			return attemptResult{retry: true}
		case <-ctx.Done():
			cleanupAttempt(t, cancel, client, eventSink, attempt, "Context cancelled")
			return attemptResult{retry: true}
		case event := <-eventSink:
			result := handleEvent(t, event, attempt)
			if result.success || result.retry {
				if result.success || result.retry {
					cancel()
					client.StopEventSink(eventSink)
				}
				return result
			}
			// Continue waiting for more events
		}
	}
}

// sendQueryAndWait sends a channel query and waits for the reply with retry logic
func sendQueryAndWait(t *testing.T, client *thin.ThinClient, channelID uint16, message []byte, nodeID *[32]byte, queueID []byte) []byte {
	maxRetries := 5
	retryDelay := 5 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		t.Logf("Sending channel query (attempt %d/%d)", attempt, maxRetries)

		eventSink := client.EventSink()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		err := client.SendChannelQuery(ctx, channelID, message, nodeID, queueID)
		require.NoError(t, err)

		result := waitForReply(t, client, eventSink, ctx, cancel, attempt)

		if result.success {
			return result.payload
		}

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
	bobChannelID, _, err := bobThinClient.CreateReadChannel(ctx, readCap, nil)
	require.NoError(t, err)
	t.Logf("Bob: Created read channel %d", bobChannelID)

	// Alice writes message
	originalMessage := []byte("Hello from Alice to Bob via new channel API!")
	t.Log("Alice: Writing message")
	writePayload, _, err := aliceThinClient.WriteChannel(ctx, channelID, originalMessage)
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

	// Wait for message propagation - increased delay for CI stability
	time.Sleep(10 * time.Second)

	// Bob reads message using the helper function
	t.Log("Bob: Reading message")
	messageID := bobThinClient.NewMessageID()
	readPayload, _, replyIndex, err := bobThinClient.ReadChannel(ctx, bobChannelID, messageID, nil)
	require.NoError(t, err)
	require.NotNil(t, readPayload)
	t.Logf("Bob: Generated read payload (%d bytes), replyIndex: %v", len(readPayload), replyIndex)

	// Bob sends read query and waits for reply using helper
	t.Log("Bob: Sending read query and waiting for reply...")
	receivedPayload := sendQueryAndWait(t, bobThinClient, bobChannelID, readPayload, &identityHash, courierService.RecipientQueueID)
	require.NotNil(t, receivedPayload, "Bob: Received nil payload")

	require.Equal(t, originalMessage, receivedPayload, "Bob should receive the original message")

	aliceThinClient.CloseChannel(ctx, channelID)
	bobThinClient.CloseChannel(ctx, bobChannelID)
}
