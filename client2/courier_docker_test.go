//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/stretchr/testify/require"
)

func testDockerCourierService(t *testing.T) {
	t.Log("TESTING COURIER SERVICE - Starting pigeonhole channel test")

	// Setup clients and test data
	aliceThinClient, bobThinClient := setupCourierTest(t)
	defer func() {
		t.Log("Test Completed. Disconnecting...")
		aliceThinClient.Close()
		bobThinClient.Close()
	}()

	// Test message to send
	plaintextMessage := []byte("Hello world from Alice to Bob!")

	// Alice sends message
	_, readCap := performAliceWriteOperation(t, aliceThinClient, plaintextMessage)

	// Bob reads message
	receivedMessage := performBobReadOperation(t, bobThinClient, readCap)

	// Verify results
	require.Equal(t, plaintextMessage, receivedMessage)
}

// setupCourierTest initializes thin clients and test data
func setupCourierTest(t *testing.T) (*thin.ThinClient, *thin.ThinClient) {
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

	return aliceThinClient, bobThinClient
}

// performAliceWriteOperation handles Alice's write channel creation and message sending
func performAliceWriteOperation(t *testing.T, aliceThinClient *thin.ThinClient, plaintextMessage []byte) (uint16, *bacap.ReadCap) {
	// Create context with timeout for operations
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// === ALICE (Writer) ===
	t.Log("Alice: Creating pigeonhole write channel")
	aliceChannelID, readCap, boxOwnerCap, currentIndex, err := aliceThinClient.CreateWriteChannel(ctx, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, aliceChannelID)
	require.NotNil(t, readCap)
	require.NotNil(t, boxOwnerCap)
	require.NotNil(t, currentIndex)
	t.Logf("Alice: Created write channel %d", aliceChannelID)

	t.Log("Alice: Preparing write message (new crash-consistent API)")
	sendPayload, nextIndex, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, plaintextMessage)
	require.NoError(t, err)
	require.NotNil(t, sendPayload)
	require.NotNil(t, nextIndex)
	t.Logf("Alice: Prepared message payload (%d bytes), next index ready", len(sendPayload))

	t.Log("Alice: Sending prepared message via SendMessage")

	// get the courier service from the PKI document
	doc := aliceThinClient.PKIDocument()
	require.NotNil(t, doc)
	serviceNodeID, courierQueueID := thin.GetRandomCourier(doc)

	writeReply := sendAndWait(t, aliceThinClient, sendPayload, serviceNodeID, courierQueueID)
	require.NotNil(t, writeReply)
	require.NotEmpty(t, writeReply)
	t.Log("Alice: Successfully sent message via sendAndWait")

	// In a real application, Alice would save nextIndex to persistent storage
	// after receiving courier acknowledgment, but for this test we'll just log it
	t.Logf("Alice: Next index for crash recovery: %v", nextIndex != nil)

	// Wait for message to propagate through the system
	t.Log("Waiting 3 seconds for message propagation...")
	time.Sleep(3 * time.Second)

	return aliceChannelID, readCap
}

// performBobReadOperation handles Bob's read channel creation and message reading
func performBobReadOperation(t *testing.T, bobThinClient *thin.ThinClient, readCap *bacap.ReadCap) []byte {
	// Create context with timeout for operations
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// === BOB (Reader) ===
	t.Log("Bob: Creating read channel from Alice's readCap (new crash-consistent API)")
	bobChannelID, bobCurrentIndex, err := bobThinClient.CreateReadChannel(ctx, readCap, nil)
	require.NoError(t, err)
	require.NotNil(t, bobChannelID)
	require.NotNil(t, bobCurrentIndex)
	t.Logf("Bob: Created read channel %d", bobChannelID)
	t.Logf("Bob: Starting read index: %v", bobCurrentIndex != nil)

	// Bob reads the message using new crash-consistent API
	// Use a consistent message ID for all read attempts to enable courier envelope reuse
	readMessageID := bobThinClient.NewMessageID()
	t.Logf("Bob: Using message ID %x for all read attempts", readMessageID[:])

	// Prepare read query
	t.Log("Bob: Preparing read query (new crash-consistent API)")
	sendPayload, nextIndex, err := bobThinClient.ReadChannel(ctx, bobChannelID, readMessageID)
	require.NoError(t, err)
	require.NotNil(t, sendPayload)
	require.NotNil(t, nextIndex)
	t.Logf("Bob: Prepared read query payload (%d bytes), next index ready", len(sendPayload))

	// get the courier service from the PKI document
	doc := bobThinClient.PKIDocument()
	require.NotNil(t, doc)
	serviceNodeID, courierQueueID := thin.GetRandomCourier(doc)

	// Send read query
	receivedMessage := sendAndWait(t, bobThinClient, sendPayload, serviceNodeID, courierQueueID)

	return receivedMessage
}
