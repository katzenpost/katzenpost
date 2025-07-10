//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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

func TestChannelClose(t *testing.T) {
	t.Log("TESTING CHANNEL CLOSE")
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Log("Alice: Creating write channel")
	channelID, _, writeCap, err := aliceThinClient.CreateWriteChannel(ctx)
	require.NoError(t, err)

	t.Log("Alice: Closing channel")
	err = aliceThinClient.CloseChannel(ctx, channelID)
	require.NoError(t, err)

	t.Log("Alice: Resuming write channel")
	channelID, err = aliceThinClient.ResumeWriteChannel(ctx, writeCap, nil, nil, nil)
	require.NoError(t, err)

	t.Log("Alice: Resuming write channel with nil message box index")
	_, err = aliceThinClient.ResumeWriteChannel(ctx, writeCap, nil, nil, nil)
	require.Error(t, err)

	t.Log("Alice: Closing channel")
	err = aliceThinClient.CloseChannel(ctx, channelID)
	require.NoError(t, err)

	t.Log("Alice: Creating write channel")
	channelID, _, writeCap, err = aliceThinClient.CreateWriteChannel(ctx)
	require.NoError(t, err)

	t.Log("Alice: Closing channel")
	err = aliceThinClient.CloseChannel(ctx, channelID)
	require.NoError(t, err)

	t.Log("done.")
}

func TestChannelAPIBasics(t *testing.T) {
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
	aliceChannelID, readCap, _, err := aliceThinClient.CreateWriteChannel(ctx)
	require.NoError(t, err)
	t.Logf("Alice: Created write channel %d", aliceChannelID)

	// Bob creates read channel
	t.Log("Bob: Creating read channel")
	bobChannelID, err := bobThinClient.CreateReadChannel(ctx, readCap)
	require.NoError(t, err)
	t.Logf("Bob: Created read channel %d", bobChannelID)

	// Alice writes message and waits for completion
	originalMessage := []byte("hello1")
	t.Log("Alice: Writing message and waiting for completion")

	// Use WriteChannelWithRetry to write and wait for completion
	aliceWriteReply, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, originalMessage)
	require.NoError(t, err)
	require.Equal(t, aliceWriteReply.ErrorCode, thin.ThinClientSuccess, "Alice: Write operation failed")
	t.Log("Alice: Write operation completed successfully")

	destNode, destQueue, err := aliceThinClient.GetCourierDestination()
	require.NoError(t, err)
	aliceMessageID := aliceThinClient.NewMessageID()

	for i := 0; i < 2; i++ {
		t.Logf("Alice: write attempt %d", i+1)
		_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, aliceWriteReply.SendMessagePayload, destNode, destQueue, aliceMessageID)
		require.NoError(t, err)
	}

	// alice writes a second message
	secondMessage := []byte("hello2")
	t.Log("Alice: Writing second message and waiting for completion")

	aliceWriteReply, err = aliceThinClient.WriteChannel(ctx, aliceChannelID, secondMessage)
	require.NoError(t, err)
	require.Equal(t, aliceWriteReply.ErrorCode, thin.ThinClientSuccess, "Alice: Write operation failed")
	t.Log("Alice: Second write operation completed successfully")

	for i := 0; i < 2; i++ {
		t.Logf("Alice: second write attempt %d", i+1)
		_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, aliceWriteReply.SendMessagePayload, destNode, destQueue, aliceMessageID)
		require.NoError(t, err)
	}
	// Wait for message propagation to storage replicas
	//time.Sleep(10 * time.Second)

	// Bob reads message using the helper function with automatic retry logic
	t.Log("Bob: Reading message with automatic reply index retry")
	readReply, err := bobThinClient.ReadChannel(ctx, bobChannelID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, readReply.ErrorCode, thin.ThinClientSuccess, "Bob: Read operation failed")

	// bob reads first message
	bobMessageID := bobThinClient.NewMessageID()
	var bobReplyPayload []byte
	for i := 0; i < 10; i++ {
		t.Logf("Bob: read attempt %d", i+1)
		bobReplyPayload, err = bobThinClient.SendChannelQueryAwaitReply(ctx, bobChannelID, readReply.SendMessagePayload, destNode, destQueue, bobMessageID)
		require.NoError(t, err)

		if len(bobReplyPayload) > 0 {
			break
		}
	}
	require.Equal(t, originalMessage, bobReplyPayload, "Bob: Reply payload mismatch")

	// bob reads second message
	bobMessageID = bobThinClient.NewMessageID()
	for i := 0; i < 10; i++ {
		t.Logf("Bob: second read attempt %d", i+1)
		bobReplyPayload, err = bobThinClient.SendChannelQueryAwaitReply(ctx, bobChannelID, readReply.SendMessagePayload, destNode, destQueue, bobMessageID)
		require.NoError(t, err)

		if len(bobReplyPayload) > 0 {
			break
		}
	}
	require.Equal(t, secondMessage, bobReplyPayload, "Bob: Second reply payload mismatch")

	aliceThinClient.CloseChannel(ctx, aliceChannelID)
	bobThinClient.CloseChannel(ctx, bobChannelID)
}

func TestResumeQuery(t *testing.T) {
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()

	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	currentDoc := validatePKIDocument(t, aliceThinClient)
	currentEpoch := currentDoc.Epoch
	t.Logf("Using PKI document for epoch %d", currentEpoch)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Alice creates write channel
	t.Log("Alice: Creating write channel")
	aliceChannelID, readCap, writeCap, err := aliceThinClient.CreateWriteChannel(ctx)
	require.NoError(t, err)
	t.Logf("Alice: Created write channel %d", aliceChannelID)

	alicePayload1 := []byte("Hello, Bob!")
	writeChannelReply, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, alicePayload1)
	require.NoError(t, err)

	aliceThinClient.CloseChannel(ctx, aliceChannelID)

	t.Log("Alice: Resuming write channel")
	aliceChannelID, err = aliceThinClient.ResumeWriteChannel(
		ctx,
		writeCap,
		writeChannelReply.NextMessageIndex,
		writeChannelReply.EnvelopeDescriptor,
		writeChannelReply.EnvelopeHash)

	require.NoError(t, err)
	require.NotZero(t, aliceChannelID, "Alice: Resume write channel failed")

	// Bob creates read channel
	t.Log("Bob: Creating read channel")
	bobChannelID, err := bobThinClient.CreateReadChannel(ctx, readCap)
	require.NoError(t, err)
	t.Logf("Bob: Created read channel %d", bobChannelID)

	// Bob reads message using the helper function with automatic retry logic
	t.Log("Bob: Reading message with automatic reply index retry")
	readReply, err := bobThinClient.ReadChannel(ctx, bobChannelID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, readReply.ErrorCode, thin.ThinClientSuccess, "Bob: Read operation failed")

	bobThinClient.CloseChannel(ctx, bobChannelID)

	t.Log("Bob: Resuming read channel")
	bobChannelID, err = bobThinClient.ResumeReadChannel(ctx, readCap, readReply.NextMessageIndex, nil, readReply.EnvelopeDescriptor, readReply.EnvelopeHash)
	require.NoError(t, err)
	require.NotZero(t, bobChannelID, "Bob: Resume read channel failed")

}
