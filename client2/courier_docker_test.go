//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"crypto/hmac"
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
	aliceChannelID, readCap := performAliceWriteOperation(t, aliceThinClient, plaintextMessage)

	// Bob reads message
	receivedMessage := performBobReadOperation(t, bobThinClient, readCap, aliceChannelID)

	// Verify results
	verifyMessageTransmission(t, plaintextMessage, receivedMessage)
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
func performAliceWriteOperation(t *testing.T, aliceThinClient *thin.ThinClient, plaintextMessage []byte) (*[thin.ChannelIDLength]byte, *bacap.UniversalReadCap) {
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
	t.Logf("Alice: Created write channel %x", aliceChannelID[:])

	t.Log("Alice: Preparing write message (new crash-consistent API)")
	sendPayload, nextIndex, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, plaintextMessage)
	require.NoError(t, err)
	require.NotNil(t, sendPayload)
	require.NotNil(t, nextIndex)
	t.Logf("Alice: Prepared message payload (%d bytes), next index ready", len(sendPayload))

	t.Log("Alice: Sending prepared message via SendMessage")
	messageID := aliceThinClient.NewMessageID()
	err = aliceThinClient.SendMessage(messageID, sendPayload, nil, nil)
	require.NoError(t, err)
	t.Log("Alice: Successfully sent message via SendMessage")

	// In a real application, Alice would save nextIndex to persistent storage
	// after receiving courier acknowledgment, but for this test we'll just log it
	t.Logf("Alice: Next index for crash recovery: %v", nextIndex != nil)

	// Wait for message to propagate through the system
	t.Log("Waiting 10 seconds for message propagation...")
	time.Sleep(10 * time.Second)

	return aliceChannelID, readCap
}

// performBobReadOperation handles Bob's read channel creation and message reading
func performBobReadOperation(t *testing.T, bobThinClient *thin.ThinClient, readCap *bacap.UniversalReadCap, aliceChannelID *[thin.ChannelIDLength]byte) []byte {
	// Create context with timeout for operations
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// === BOB (Reader) ===
	t.Log("Bob: Creating read channel from Alice's readCap (new crash-consistent API)")
	bobChannelID, bobCurrentIndex, err := bobThinClient.CreateReadChannel(ctx, readCap, nil)
	require.NoError(t, err)
	require.NotNil(t, bobChannelID)
	require.NotNil(t, bobCurrentIndex)
	t.Logf("Bob: Created read channel %x (different from Alice's %x)", bobChannelID[:], aliceChannelID[:])
	t.Logf("Bob: Starting read index: %v", bobCurrentIndex != nil)

	// Bob reads the message using new crash-consistent API
	// Use a consistent message ID for all read attempts to enable courier envelope reuse
	readMessageID := bobThinClient.NewMessageID()
	t.Logf("Bob: Using message ID %x for all read attempts", readMessageID[:])

	return attemptMessageRead(t, bobThinClient, bobChannelID, readMessageID)
}

// attemptMessageRead performs the retry logic for reading messages
func attemptMessageRead(t *testing.T, bobThinClient *thin.ThinClient, bobChannelID *[thin.ChannelIDLength]byte, readMessageID *[thin.MessageIDLength]byte) []byte {
	maxRetries := 10
	messageReceived := false
	var receivedMessage []byte

	for i := 0; i < maxRetries && !messageReceived; i++ {
		t.Logf("Bob: Reading message attempt %d/%d (new crash-consistent API)", i+1, maxRetries)

		// Add a longer delay before the first read to allow message propagation
		if i == 0 {
			t.Log("Bob: Waiting for message to propagate through the system...")
			time.Sleep(5 * time.Second)
		}

		params := &ReadAttemptParams{
			BobThinClient:   bobThinClient,
			BobChannelID:    bobChannelID,
			ReadMessageID:   readMessageID,
			AttemptNum:      i,
			MaxRetries:      maxRetries,
			ReceivedMessage: &receivedMessage,
			MessageReceived: &messageReceived,
		}
		if performSingleReadAttempt(t, params) {
			break
		}
	}

	return receivedMessage
}

// ReadAttemptParams groups parameters for read attempt operations
type ReadAttemptParams struct {
	BobThinClient   *thin.ThinClient
	BobChannelID    *[thin.ChannelIDLength]byte
	ReadMessageID   *[thin.MessageIDLength]byte
	AttemptNum      int
	MaxRetries      int
	ReceivedMessage *[]byte
	MessageReceived *bool
}

// performSingleReadAttempt performs a single read attempt with proper error handling
func performSingleReadAttempt(t *testing.T, params *ReadAttemptParams) bool {
	// Create a fresh context with 10-minute timeout for each read attempt
	readCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Step 1: Prepare read query (new API)
	t.Logf("Bob: Preparing read query for attempt %d", params.AttemptNum+1)
	readPayload, nextReadIndex, err := params.BobThinClient.ReadChannel(readCtx, params.BobChannelID, params.ReadMessageID)
	if err != nil {
		return handleReadPreparationError(t, err, params.AttemptNum, params.MaxRetries)
	}

	t.Logf("Bob: Prepared read query (%d bytes), next index ready", len(readPayload))

	// Step 2: Get PKI document and select random courier
	doc := params.BobThinClient.PKIDocument()
	if doc == nil {
		t.Fatalf("Bob: Failed to get PKI document: PKI document is nil")
	}

	// Step 3: Select random courier for sending the read query
	destinationIdHash, recipientQueueID := thin.GetRandomCourier(doc)

	// Step 4: Send prepared query via SendMessage
	t.Logf("Bob: Sending prepared read query via SendMessage")
	surbID := params.BobThinClient.NewSURBID()
	err = params.BobThinClient.SendMessage(surbID, readPayload, destinationIdHash, recipientQueueID)
	if err != nil {
		return handleSendMessageError(t, err, params.AttemptNum, params.MaxRetries)
	}

	// Step 3: Wait for reply via MessageReplyEvent
	replyParams := &ReplyWaitParams{
		BobThinClient:   params.BobThinClient,
		ReadMessageID:   params.ReadMessageID,
		SURBID:          surbID,
		NextReadIndex:   nextReadIndex,
		AttemptNum:      params.AttemptNum,
		MaxRetries:      params.MaxRetries,
		ReceivedMessage: params.ReceivedMessage,
		MessageReceived: params.MessageReceived,
	}
	return waitForMessageReply(t, replyParams)
}

// handleReadPreparationError handles errors during read preparation
func handleReadPreparationError(t *testing.T, err error, attemptNum, maxRetries int) bool {
	t.Logf("Bob: Read preparation attempt %d failed: %v", attemptNum+1, err)
	if attemptNum < maxRetries-1 {
		time.Sleep(3 * time.Second) // Wait before retry
		return false
	}
	t.Logf("Bob: Final read preparation failed: %v", err)
	return true
}

// handleSendMessageError handles errors during SendMessage
func handleSendMessageError(t *testing.T, err error, attemptNum, maxRetries int) bool {
	t.Logf("Bob: SendMessage attempt %d failed: %v", attemptNum+1, err)
	if attemptNum < maxRetries-1 {
		time.Sleep(3 * time.Second) // Wait before retry
		return false
	}
	t.Logf("Bob: Final SendMessage failed: %v", err)
	return true
}

// ReplyWaitParams groups parameters for waiting for message replies
type ReplyWaitParams struct {
	BobThinClient   *thin.ThinClient
	ReadMessageID   *[thin.MessageIDLength]byte
	SURBID          *[16]byte
	NextReadIndex   *bacap.MessageBoxIndex
	AttemptNum      int
	MaxRetries      int
	ReceivedMessage *[]byte
	MessageReceived *bool
}

// waitForMessageReply waits for and processes MessageReplyEvent
func waitForMessageReply(t *testing.T, params *ReplyWaitParams) bool {
	t.Log("Bob: Waiting for MessageReplyEvent with actual message content...")

	// Wait for the reply with a reasonable timeout
	replyCtx, replyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer replyCancel()

	// Wait for the actual reply event
	select {
	case event := <-params.BobThinClient.EventSink():
		eventParams := &EventProcessParams{
			ReadMessageID:   params.ReadMessageID,
			SURBID:          params.SURBID,
			NextReadIndex:   params.NextReadIndex,
			AttemptNum:      params.AttemptNum,
			MaxRetries:      params.MaxRetries,
			ReceivedMessage: params.ReceivedMessage,
			MessageReceived: params.MessageReceived,
		}
		return processReplyEvent(t, event, eventParams)
	case <-replyCtx.Done():
		return handleReplyTimeout(t, params.AttemptNum, params.MaxRetries)
	}
}

// EventProcessParams groups parameters for processing reply events
type EventProcessParams struct {
	ReadMessageID   *[thin.MessageIDLength]byte
	SURBID          *[16]byte
	NextReadIndex   *bacap.MessageBoxIndex
	AttemptNum      int
	MaxRetries      int
	ReceivedMessage *[]byte
	MessageReceived *bool
}

// processReplyEvent processes the received event and extracts the message
func processReplyEvent(t *testing.T, event thin.Event, params *EventProcessParams) bool {
	switch e := event.(type) {
	case *thin.MessageReplyEvent:
		// Check if this reply matches our SURB ID using constant-time comparison
		if e.SURBID != nil && params.SURBID != nil && hmac.Equal(e.SURBID[:], params.SURBID[:]) {
			replyParams := &MessageReplyParams{
				Event:           e,
				NextReadIndex:   params.NextReadIndex,
				AttemptNum:      params.AttemptNum,
				MaxRetries:      params.MaxRetries,
				ReceivedMessage: params.ReceivedMessage,
				MessageReceived: params.MessageReceived,
			}
			return handleCorrectMessageReply(t, replyParams)
		}
		return handleWrongSURBID(t, params.AttemptNum, params.MaxRetries)
	default:
		return handleUnexpectedEvent(t, e, params.AttemptNum, params.MaxRetries)
	}
}

// MessageReplyParams groups parameters for handling message replies
type MessageReplyParams struct {
	Event           *thin.MessageReplyEvent
	NextReadIndex   *bacap.MessageBoxIndex
	AttemptNum      int
	MaxRetries      int
	ReceivedMessage *[]byte
	MessageReceived *bool
}

// handleCorrectMessageReply processes a MessageReplyEvent with the correct message ID
func handleCorrectMessageReply(t *testing.T, params *MessageReplyParams) bool {
	t.Log("Bob: Received MessageReplyEvent for our read query")
	if params.Event.ErrorCode != thin.ThinClientErrorSuccess {
		t.Logf("Bob: MessageReplyEvent contains error: %v", thin.ThinClientErrorToString(params.Event.ErrorCode))
		if params.AttemptNum < params.MaxRetries-1 {
			time.Sleep(3 * time.Second)
			return false
		}
		t.Fatalf("Bob: Final MessageReplyEvent failed: %v", thin.ThinClientErrorToString(params.Event.ErrorCode))
	}

	// Extract the actual message from the reply
	if len(params.Event.Payload) > 0 {
		*params.ReceivedMessage = params.Event.Payload
		t.Logf("Bob: Successfully received message (%d bytes)", len(*params.ReceivedMessage))
		t.Logf("Bob: Next read index for crash recovery: %v", params.NextReadIndex != nil)
		*params.MessageReceived = true
		return true
	}

	t.Log("Bob: MessageReplyEvent has empty payload, retrying...")
	if params.AttemptNum < params.MaxRetries-1 {
		time.Sleep(3 * time.Second)
		return false
	}
	t.Fatal("Bob: Final MessageReplyEvent had empty payload")
	return true
}

// handleWrongSURBID handles MessageReplyEvent with wrong SURB ID
func handleWrongSURBID(t *testing.T, attemptNum, maxRetries int) bool {
	t.Logf("Bob: Received MessageReplyEvent for different SURB ID, ignoring")
	if attemptNum < maxRetries-1 {
		time.Sleep(3 * time.Second)
		return false
	}
	t.Fatal("Bob: Never received MessageReplyEvent for our read query")
	return true
}

// handleUnexpectedEvent handles unexpected event types
func handleUnexpectedEvent(t *testing.T, e thin.Event, attemptNum, maxRetries int) bool {
	t.Logf("Bob: Received unexpected event type: %T, ignoring", e)
	if attemptNum < maxRetries-1 {
		time.Sleep(3 * time.Second)
		return false
	}
	t.Fatal("Bob: Never received MessageReplyEvent for our read query")
	return true
}

// handleReplyTimeout handles timeout waiting for MessageReplyEvent
func handleReplyTimeout(t *testing.T, attemptNum, maxRetries int) bool {
	t.Logf("Bob: Timeout waiting for MessageReplyEvent on attempt %d", attemptNum+1)
	if attemptNum < maxRetries-1 {
		time.Sleep(3 * time.Second)
		return false
	}
	t.Fatal("Bob: Final timeout waiting for MessageReplyEvent")
	return true
}

// verifyMessageTransmission verifies that the message was transmitted correctly
func verifyMessageTransmission(t *testing.T, plaintextMessage, receivedMessage []byte) {
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

	t.Log("SUCCESS: New crash-consistent channel API test completed!")
	t.Log("✅ Alice successfully created write channel with BoxOwnerCap and MessageBoxIndex")
	t.Log("✅ Alice successfully prepared and sent message using new two-stage API")
	t.Log("✅ Bob successfully created read channel with MessageBoxIndex")
	t.Log("✅ Bob successfully prepared read query using new two-stage API")
	t.Logf("Original message: %s", string(plaintextMessage))
	t.Logf("Received message: %s", string(receivedMessage))
	t.Log("🎉 Crash-consistent channel API is working correctly!")
}
