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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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

	// Alice writes message and waits for completion
	originalMessage := []byte("Hello from Alice to Bob via new channel API!")
	t.Log("Alice: Writing message and waiting for completion")

	// Get courier service info
	epochDoc, err := aliceThinClient.PKIDocumentForEpoch(currentEpoch)
	require.NoError(t, err)
	courierServices := common.FindServices("courier", epochDoc)
	require.True(t, len(courierServices) > 0, "No courier services found")
	courierService := courierServices[0]
	identityHash := hash.Sum256(courierService.MixDescriptor.IdentityKey)

	// Use WriteChannelWithReply to write and wait for completion
	err = aliceThinClient.WriteChannelWithRetry(ctx, channelID, originalMessage, &identityHash, courierService.RecipientQueueID)
	require.NoError(t, err)
	t.Log("Alice: Write operation completed successfully")

	// Wait for message propagation to storage replicas
	time.Sleep(10 * time.Second)

	// Bob reads message using the helper function with automatic retry logic
	t.Log("Bob: Reading message with automatic reply index retry")
	receivedPayload, err := bobThinClient.ReadChannelWithRetry(ctx, bobChannelID, &identityHash, courierService.RecipientQueueID)
	require.NoError(t, err)
	require.NotNil(t, receivedPayload, "Bob: Received nil payload")

	require.Equal(t, originalMessage, receivedPayload, "Bob should receive the original message")

	aliceThinClient.CloseChannel(ctx, channelID)
	bobThinClient.CloseChannel(ctx, bobChannelID)
}

// TestDockerCourierServiceSingleReadQuery tests that after a write has been committed and replicated,
// the courier returns the payload on the first read query without any retries.
// This test validates the synchronous proxy behavior where intermediary replicas proxy requests
// to destination replicas and return the data in a single request-response cycle.
func TestDockerCourierServiceSingleReadQuery(t *testing.T) {
	t.Log("TESTING COURIER SERVICE - Single Read Query (No Retries)")

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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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

	// Alice writes message and waits for completion
	originalMessage := []byte("Single read test: Hello from Alice to Bob!")
	t.Log("Alice: Writing message and waiting for completion")

	// Get courier service info
	epochDoc, err := aliceThinClient.PKIDocumentForEpoch(currentEpoch)
	require.NoError(t, err)
	courierServices := common.FindServices("courier", epochDoc)
	require.True(t, len(courierServices) > 0, "No courier services found")
	courierService := courierServices[0]
	identityHash := hash.Sum256(courierService.MixDescriptor.IdentityKey)

	// Use WriteChannelWithRetry to write and wait for completion
	err = aliceThinClient.WriteChannelWithRetry(ctx, channelID, originalMessage, &identityHash, courierService.RecipientQueueID)
	require.NoError(t, err)
	t.Log("Alice: Write operation completed successfully")

	// Wait for message propagation to storage replicas
	t.Log("Waiting for message propagation to storage replicas...")
	time.Sleep(10 * time.Second)

	// Bob performs SINGLE read query without retries
	t.Log("Bob: Performing SINGLE read query (no retries)")

	// Generate a unique messageID for this read operation
	readMessageID := bobThinClient.NewMessageID()

	// Prepare read query with reply index 0
	replyIndex := uint8(0)
	readPayload, _, _, err := bobThinClient.ReadChannel(ctx, bobChannelID, readMessageID, &replyIndex)
	require.NoError(t, err)
	t.Logf("Bob: Prepared read query with messageID %x and reply index %d", readMessageID[:8], replyIndex)

	// Send the single read query
	err = bobThinClient.SendChannelQuery(ctx, bobChannelID, readPayload, &identityHash, courierService.RecipientQueueID, readMessageID)
	require.NoError(t, err)
	t.Log("Bob: Sent single read query to courier")

	// Wait for the response using event sink
	eventSink := bobThinClient.EventSink()
	defer bobThinClient.StopEventSink(eventSink)

	readCtx, readCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer readCancel()

	var receivedPayload []byte
	var responseReceived bool

	// Wait for a single response - no infinite loop
	select {
	case event := <-eventSink:
		switch v := event.(type) {
		case *thin.MessageReplyEvent:
			// Check if this reply matches our expected messageID
			if v.MessageID != nil && *v.MessageID == *readMessageID {
				t.Logf("Bob: Received MessageReplyEvent for messageID %x: Err=%s, PayloadLen=%d",
					readMessageID[:8], v.Err, len(v.Payload))

				if v.Err != "" {
					t.Fatalf("Single read query failed with error: %s", v.Err)
				}

				receivedPayload = v.Payload
				responseReceived = true
			} else {
				t.Fatal("Received reply for unexpected messageID or nil messageID")
			}

		case *thin.ConnectionStatusEvent:
			if !v.IsConnected {
				t.Fatal("Connection lost during read query")
			} else {
				t.Fatal("Received connection status event instead of message reply")
			}
		default:
			t.Fatalf("Received unexpected event type: %T", event)
		}
	case <-readCtx.Done():
		t.Fatal("Timeout waiting for single read query response")
	case <-bobThinClient.HaltCh():
		t.Fatal("Client halted during read query")
	}

	if !responseReceived {
		t.Fatal("No valid response received for single read query")
	}

	// Test MUST fail if we get nil or zero-length payload
	require.NoError(t, err, "Single read query must succeed")
	require.NotNil(t, receivedPayload, "Single read query must return non-nil payload")
	require.Greater(t, len(receivedPayload), 0, "Single read query must return non-empty payload - proxy functionality failed")

	// Payload must match what Alice originally sent
	require.Equal(t, originalMessage, receivedPayload, "Bob should receive the exact message Alice sent")

	t.Logf("SUCCESS: Single read query returned payload of %d bytes: %s", len(receivedPayload), string(receivedPayload))
	t.Log("SUCCESS: Courier + replicas responded to read query with a single query - proxy functionality working correctly")

	aliceThinClient.CloseChannel(ctx, channelID)
	bobThinClient.CloseChannel(ctx, bobChannelID)
}
