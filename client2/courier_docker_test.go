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
	time.Sleep(5 * time.Second)

	// Bob reads message using the helper function with automatic retry logic
	t.Log("Bob: Reading message with automatic reply index retry")
	receivedPayload, err := bobThinClient.ReadChannelWithRetry(ctx, bobChannelID, &identityHash, courierService.RecipientQueueID)
	require.NoError(t, err)
	require.NotNil(t, receivedPayload, "Bob: Received nil payload")

	require.Equal(t, originalMessage, receivedPayload, "Bob should receive the original message")

	aliceThinClient.CloseChannel(ctx, channelID)
	bobThinClient.CloseChannel(ctx, bobChannelID)
}
