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

// note that this test is meaningful although the close command does not
// have a corresponding reply type to tell us if the close failed or not.
func TestChannelClose(t *testing.T) {
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	channelID, _, writeCap, err := aliceThinClient.CreateWriteChannel(ctx)
	require.NoError(t, err)

	// closing the channel erases the daemon's internal state tracking that channel
	err = aliceThinClient.CloseChannel(ctx, channelID)
	require.NoError(t, err)

	// we should be able to resume now that the channel is gone
	channelID, err = aliceThinClient.ResumeWriteChannel(ctx, writeCap, nil)
	require.NoError(t, err)

	// resuming again should fail because the writeCap is already in use
	_, err = aliceThinClient.ResumeWriteChannel(ctx, writeCap, nil)
	require.Error(t, err)

	// closing the channel again should work
	err = aliceThinClient.CloseChannel(ctx, channelID)
	require.NoError(t, err)
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
	aliceWriteReply1, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, originalMessage)
	require.NoError(t, err)
	require.Equal(t, aliceWriteReply1.ErrorCode, thin.ThinClientSuccess, "Alice: Write operation failed")
	t.Log("Alice: Write operation completed successfully")

	destNode, destQueue, err := aliceThinClient.GetCourierDestination()
	require.NoError(t, err)
	aliceMessageID1 := aliceThinClient.NewMessageID()

	_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, aliceWriteReply1.SendMessagePayload, destNode, destQueue, aliceMessageID1)
	require.NoError(t, err)

	// alice writes a second message
	secondMessage := []byte("hello2")
	t.Log("Alice: Writing second message and waiting for completion")

	aliceWriteReply2, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, secondMessage)
	require.NoError(t, err)
	require.Equal(t, aliceWriteReply2.ErrorCode, thin.ThinClientSuccess, "Alice: Write operation failed")
	t.Log("Alice: Second write operation completed successfully")

	aliceMessageID2 := aliceThinClient.NewMessageID()

	_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, aliceWriteReply2.SendMessagePayload, destNode, destQueue, aliceMessageID2)
	require.NoError(t, err)

	// Wait for message propagation to storage replicas
	t.Log("Waiting for message propagation to storage replicas")
	time.Sleep(10 * time.Second)

	// Bob reads first message
	t.Log("Bob: Reading first message")
	readReply1, err := bobThinClient.ReadChannel(ctx, bobChannelID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, readReply1.ErrorCode, thin.ThinClientSuccess, "Bob: Read operation failed")

	bobMessageID1 := bobThinClient.NewMessageID()
	var bobReplyPayload []byte

	for i := 0; i < 10; i++ {
		bobReplyPayload, err = bobThinClient.SendChannelQueryAwaitReply(ctx, bobChannelID, readReply1.SendMessagePayload, destNode, destQueue, bobMessageID1)
		require.NoError(t, err)
		if len(bobReplyPayload) > 0 {
			break
		}
	}
	require.Equal(t, originalMessage, bobReplyPayload, "Bob: Reply payload mismatch")

	// Bob reads second message
	t.Log("Bob: Reading second message")
	readReply2, err := bobThinClient.ReadChannel(ctx, bobChannelID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, readReply2.ErrorCode, thin.ThinClientSuccess, "Bob: Second read operation failed")

	bobMessageID2 := bobThinClient.NewMessageID()
	for i := 0; i < 10; i++ {
		t.Logf("Bob: second read attempt %d", i+1)
		bobReplyPayload, err = bobThinClient.SendChannelQueryAwaitReply(ctx, bobChannelID, readReply2.SendMessagePayload, destNode, destQueue, bobMessageID2)
		require.NoError(t, err)

		if len(bobReplyPayload) > 0 {
			break
		}
	}
	require.Equal(t, secondMessage, bobReplyPayload, "Bob: Second reply payload mismatch")

	aliceThinClient.CloseChannel(ctx, aliceChannelID)
	bobThinClient.CloseChannel(ctx, bobChannelID)
}

func TestResumeWriteChannel(t *testing.T) {
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

	destNode, destQueue, err := aliceThinClient.GetCourierDestination()
	require.NoError(t, err)
	aliceMessageID1 := aliceThinClient.NewMessageID()

	_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, writeChannelReply.SendMessagePayload, destNode, destQueue, aliceMessageID1)
	require.NoError(t, err)

	t.Log("Waiting for first message propagation to storage replicas")
	time.Sleep(3 * time.Second)

	aliceThinClient.CloseChannel(ctx, aliceChannelID)

	t.Log("Alice: Resuming write channel")
	aliceChannelID, err = aliceThinClient.ResumeWriteChannel(
		ctx,
		writeCap,
		writeChannelReply.NextMessageIndex)
	require.NoError(t, err)
	require.NotZero(t, aliceChannelID, "Alice: Resume write channel failed")
	t.Logf("Alice: Resumed write channel with ID %d", aliceChannelID)

	t.Log("Alice: Writing second message after resume")
	alicePayload2 := []byte("Second message from Alice!")
	writeChannelReply2, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, alicePayload2)
	require.NoError(t, err)
	require.Equal(t, writeChannelReply2.ErrorCode, thin.ThinClientSuccess, "Alice: Second write operation failed")

	aliceMessageID2 := aliceThinClient.NewMessageID()
	_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, writeChannelReply2.SendMessagePayload, destNode, destQueue, aliceMessageID2)
	require.NoError(t, err)
	t.Log("Alice: Second write operation completed successfully")

	t.Log("Waiting for second message propagation to storage replicas")
	time.Sleep(3 * time.Second)

	t.Log("Bob: Creating read channel")
	bobChannelID, err := bobThinClient.CreateReadChannel(ctx, readCap)
	require.NoError(t, err)
	t.Logf("Bob: Created read channel %d", bobChannelID)

	t.Log("Bob: Reading first message")
	readReply, err := bobThinClient.ReadChannel(ctx, bobChannelID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, readReply.ErrorCode, thin.ThinClientSuccess, "Bob: Read operation failed")

	// Send the first read query and get the message payload
	bobMessageID1 := bobThinClient.NewMessageID()
	var bobReplyPayload1 []byte

	for i := 0; i < 10; i++ {
		bobReplyPayload1, err = bobThinClient.SendChannelQueryAwaitReply(ctx, bobChannelID, readReply.SendMessagePayload, destNode, destQueue, bobMessageID1)
		require.NoError(t, err)
		if len(bobReplyPayload1) > 0 {
			break
		}
	}
	require.Equal(t, alicePayload1, bobReplyPayload1, "Bob: First message payload mismatch")

	t.Log("Bob: Reading second message")
	readReply2, err := bobThinClient.ReadChannel(ctx, bobChannelID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, readReply2.ErrorCode, thin.ThinClientSuccess, "Bob: Second read operation failed")

	// Send the read query and get the actual message payload
	bobMessageID2 := bobThinClient.NewMessageID()
	var bobReplyPayload2 []byte

	for i := 0; i < 10; i++ {
		t.Logf("Bob: second message read attempt %d", i+1)
		bobReplyPayload2, err = bobThinClient.SendChannelQueryAwaitReply(ctx, bobChannelID, readReply2.SendMessagePayload, destNode, destQueue, bobMessageID2)
		require.NoError(t, err)
		if len(bobReplyPayload2) > 0 {
			break
		}
	}

	// Verify the second message content matches
	require.Equal(t, alicePayload2, bobReplyPayload2, "Bob: Second message payload mismatch")
	t.Log("Bob: Successfully received and verified second message")

	// Clean up channels
	aliceThinClient.CloseChannel(ctx, aliceChannelID)
	bobThinClient.CloseChannel(ctx, bobChannelID)
}

func TestResumeWriteChannelQuery(t *testing.T) {
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

	courierNode, courierQueueID, err := aliceThinClient.GetCourierDestination()
	require.NoError(t, err)
	aliceMessageID1 := aliceThinClient.NewMessageID()

	aliceFirstWriteCiphertext := writeChannelReply.SendMessagePayload

	t.Log("Waiting for first message propagation to storage replicas")
	time.Sleep(3 * time.Second)

	aliceThinClient.CloseChannel(ctx, aliceChannelID)

	t.Log("Alice: Resuming write channel")
	aliceChannelID, err = aliceThinClient.ResumeWriteChannelQuery(
		ctx,
		writeCap,
		writeChannelReply.CurrentMessageIndex,
		writeChannelReply.EnvelopeDescriptor,
		writeChannelReply.EnvelopeHash)
	require.NoError(t, err)
	require.NotZero(t, aliceChannelID, "Alice: Resume write channel failed")
	t.Logf("Alice: Resumed write channel with ID %d", aliceChannelID)

	t.Log("Alice: Writing first message after resume")

	_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, aliceFirstWriteCiphertext, courierNode, courierQueueID, aliceMessageID1)
	require.NoError(t, err)

	t.Log("Alice: Writing second message")
	alicePayload2 := []byte("Second message from Alice!")
	writeChannelReply2, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, alicePayload2)
	require.NoError(t, err)
	require.Equal(t, writeChannelReply2.ErrorCode, thin.ThinClientSuccess, "Alice: Second write operation failed")

	aliceMessageID2 := aliceThinClient.NewMessageID()
	_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, writeChannelReply2.SendMessagePayload, courierNode, courierQueueID, aliceMessageID2)
	require.NoError(t, err)
	t.Log("Alice: Second write operation completed successfully")

	t.Log("Waiting for second message propagation to storage replicas")
	time.Sleep(3 * time.Second)

	t.Log("Bob: Creating read channel")
	bobChannelID, err := bobThinClient.CreateReadChannel(ctx, readCap)
	require.NoError(t, err)
	t.Logf("Bob: Created read channel %d", bobChannelID)

	t.Log("Bob: Reading first message")
	readReply, err := bobThinClient.ReadChannel(ctx, bobChannelID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, readReply.ErrorCode, thin.ThinClientSuccess, "Bob: Read operation failed")

	// Send the first read query and get the message payload
	bobMessageID1 := bobThinClient.NewMessageID()
	var bobReplyPayload1 []byte

	for i := 0; i < 10; i++ {
		bobReplyPayload1, err = bobThinClient.SendChannelQueryAwaitReply(ctx, bobChannelID, readReply.SendMessagePayload, courierNode, courierQueueID, bobMessageID1)
		require.NoError(t, err)
		if len(bobReplyPayload1) > 0 {
			break
		}
	}
	require.Equal(t, alicePayload1, bobReplyPayload1, "Bob: First message payload mismatch")

	t.Log("Bob: Reading second message")
	readReply2, err := bobThinClient.ReadChannel(ctx, bobChannelID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, readReply2.ErrorCode, thin.ThinClientSuccess, "Bob: Second read operation failed")

	// Send the read query and get the actual message payload
	bobMessageID2 := bobThinClient.NewMessageID()
	var bobReplyPayload2 []byte

	for i := 0; i < 10; i++ {
		t.Logf("Bob: second message read attempt %d", i+1)
		bobReplyPayload2, err = bobThinClient.SendChannelQueryAwaitReply(ctx, bobChannelID, readReply2.SendMessagePayload, courierNode, courierQueueID, bobMessageID2)
		require.NoError(t, err)
		if len(bobReplyPayload2) > 0 {
			break
		}
	}

	// Verify the second message content matches
	require.Equal(t, alicePayload2, bobReplyPayload2, "Bob: Second message payload mismatch")
	t.Log("Bob: Successfully received and verified second message")

	// Clean up channels
	aliceThinClient.CloseChannel(ctx, aliceChannelID)
	bobThinClient.CloseChannel(ctx, bobChannelID)
}

func TestResumeReadChannel(t *testing.T) {
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
	aliceChannelID, readCap, _, err := aliceThinClient.CreateWriteChannel(ctx)
	require.NoError(t, err)
	t.Logf("Alice: Created write channel %d", aliceChannelID)

	alicePayload1 := []byte("Hello, Bob!")
	writeChannelReply, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, alicePayload1)
	require.NoError(t, err)

	destNode, destQueue, err := aliceThinClient.GetCourierDestination()
	require.NoError(t, err)
	aliceMessageID1 := aliceThinClient.NewMessageID()

	_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, writeChannelReply.SendMessagePayload, destNode, destQueue, aliceMessageID1)
	require.NoError(t, err)

	t.Log("Waiting for first message propagation to storage replicas")
	time.Sleep(3 * time.Second)

	t.Log("Alice: Writing second message")
	alicePayload2 := []byte("Second message from Alice!")
	writeChannelReply2, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, alicePayload2)
	require.NoError(t, err)
	require.Equal(t, writeChannelReply2.ErrorCode, thin.ThinClientSuccess, "Alice: Second write operation failed")

	aliceMessageID2 := aliceThinClient.NewMessageID()
	_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, writeChannelReply2.SendMessagePayload, destNode, destQueue, aliceMessageID2)
	require.NoError(t, err)
	t.Log("Alice: Second write operation completed successfully")

	t.Log("Waiting for second message propagation to storage replicas")
	time.Sleep(3 * time.Second)

	t.Log("Bob: Creating read channel")
	bobChannelID, err := bobThinClient.CreateReadChannel(ctx, readCap)
	require.NoError(t, err)
	t.Logf("Bob: Created read channel %d", bobChannelID)

	t.Log("Bob: Reading first message")
	readReply, err := bobThinClient.ReadChannel(ctx, bobChannelID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, readReply.ErrorCode, thin.ThinClientSuccess, "Bob: Read operation failed")

	// Send the first read query and get the message payload
	bobMessageID1 := bobThinClient.NewMessageID()
	var bobReplyPayload1 []byte

	for i := 0; i < 10; i++ {
		bobReplyPayload1, err = bobThinClient.SendChannelQueryAwaitReply(ctx, bobChannelID, readReply.SendMessagePayload, destNode, destQueue, bobMessageID1)
		require.NoError(t, err)
		if len(bobReplyPayload1) > 0 {
			break
		}
	}
	require.Equal(t, alicePayload1, bobReplyPayload1, "Bob: First message payload mismatch")

	bobThinClient.CloseChannel(ctx, bobChannelID)

	t.Log("Bob: Resuming read channel")
	bobChannelID, err = bobThinClient.ResumeReadChannel(ctx, readCap, readReply.NextMessageIndex, readReply.ReplyIndex)
	require.NoError(t, err)
	require.NotZero(t, bobChannelID, "Bob: Resume read channel failed")
	t.Logf("Bob: Resumed read channel with ID %d", bobChannelID)

	t.Log("Bob: Reading second message")
	readReply2, err := bobThinClient.ReadChannel(ctx, bobChannelID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, readReply2.ErrorCode, thin.ThinClientSuccess, "Bob: Second read operation failed")

	// Send the read query and get the actual message payload
	bobMessageID2 := bobThinClient.NewMessageID()
	var bobReplyPayload2 []byte

	for i := 0; i < 10; i++ {
		t.Logf("Bob: second message read attempt %d", i+1)
		bobReplyPayload2, err = bobThinClient.SendChannelQueryAwaitReply(ctx, bobChannelID, readReply2.SendMessagePayload, destNode, destQueue, bobMessageID2)
		require.NoError(t, err)
		if len(bobReplyPayload2) > 0 {
			break
		}
	}

	// Verify the second message content matches
	require.Equal(t, alicePayload2, bobReplyPayload2, "Bob: Second message payload mismatch")
	t.Log("Bob: Successfully received and verified second message")

	// Clean up channels
	aliceThinClient.CloseChannel(ctx, aliceChannelID)
	bobThinClient.CloseChannel(ctx, bobChannelID)
}

func TestResumeReadChannelQuery(t *testing.T) {
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()

	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	currentDoc := validatePKIDocument(t, aliceThinClient)
	currentEpoch := currentDoc.Epoch
	t.Logf("Using PKI document for epoch %d", currentEpoch)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Log("Alice: Creating write channel")
	aliceChannelID, readCap, _, err := aliceThinClient.CreateWriteChannel(ctx)
	require.NoError(t, err)
	t.Logf("Alice: Created write channel %d", aliceChannelID)

	alicePayload1 := []byte("Hello, Bob!")
	writeChannelReply, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, alicePayload1)
	require.NoError(t, err)

	destNode, destQueue, err := aliceThinClient.GetCourierDestination()
	require.NoError(t, err)
	aliceMessageID1 := aliceThinClient.NewMessageID()

	_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, writeChannelReply.SendMessagePayload, destNode, destQueue, aliceMessageID1)
	require.NoError(t, err)

	t.Log("Waiting for first message propagation to storage replicas")
	time.Sleep(3 * time.Second)

	t.Log("Alice: Writing second message")
	alicePayload2 := []byte("Second message from Alice!")
	writeChannelReply2, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, alicePayload2)
	require.NoError(t, err)
	require.Equal(t, writeChannelReply2.ErrorCode, thin.ThinClientSuccess, "Alice: Second write operation failed")

	aliceMessageID2 := aliceThinClient.NewMessageID()
	_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, writeChannelReply2.SendMessagePayload, destNode, destQueue, aliceMessageID2)
	require.NoError(t, err)
	t.Log("Alice: Second write operation completed successfully")

	t.Log("Waiting for second message propagation to storage replicas")
	time.Sleep(3 * time.Second)

	t.Log("Bob: Creating read channel")
	bobChannelID, err := bobThinClient.CreateReadChannel(ctx, readCap)
	require.NoError(t, err)
	t.Logf("Bob: Created read channel %d", bobChannelID)

	t.Log("Bob: Reading first message")
	readReply, err := bobThinClient.ReadChannel(ctx, bobChannelID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, readReply.ErrorCode, thin.ThinClientSuccess, "Bob: Read operation failed")

	bobThinClient.CloseChannel(ctx, bobChannelID)

	t.Log("Bob: Resuming read channel")
	bobChannelID, err = bobThinClient.ResumeReadChannelQuery(
		ctx,
		readCap,
		readReply.CurrentMessageIndex,
		readReply.ReplyIndex,
		readReply.EnvelopeDescriptor,
		readReply.EnvelopeHash)
	require.NoError(t, err)
	require.NotZero(t, bobChannelID, "Bob: Resume read channel failed")
	t.Logf("Bob: Resumed read channel with ID %d", bobChannelID)

	// Send the first read query and get the message payload
	bobMessageID1 := bobThinClient.NewMessageID()
	var bobReplyPayload1 []byte

	for i := 0; i < 10; i++ {
		t.Logf("Bob: first message read attempt %d", i+1)
		bobReplyPayload1, err = bobThinClient.SendChannelQueryAwaitReply(ctx, bobChannelID, readReply.SendMessagePayload, destNode, destQueue, bobMessageID1)
		require.NoError(t, err)
		if len(bobReplyPayload1) > 0 {
			break
		}
	}
	require.Equal(t, alicePayload1, bobReplyPayload1, "Bob: First message payload mismatch")

	t.Log("Bob: Reading second message")
	readReply2, err := bobThinClient.ReadChannel(ctx, bobChannelID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, readReply2.ErrorCode, thin.ThinClientSuccess, "Bob: Second read operation failed")

	// Send the read query and get the actual message payload
	bobMessageID2 := bobThinClient.NewMessageID()
	var bobReplyPayload2 []byte

	for i := 0; i < 10; i++ {
		t.Logf("Bob: second message read attempt %d", i+1)
		bobReplyPayload2, err = bobThinClient.SendChannelQueryAwaitReply(ctx, bobChannelID, readReply2.SendMessagePayload, destNode, destQueue, bobMessageID2)
		require.NoError(t, err)
		if len(bobReplyPayload2) > 0 {
			break
		}
	}

	// Verify the second message content matches
	require.Equal(t, alicePayload2, bobReplyPayload2, "Bob: Second message payload mismatch")
	t.Log("Bob: Successfully received and verified second message")

	// Clean up channels
	aliceThinClient.CloseChannel(ctx, aliceChannelID)
	bobThinClient.CloseChannel(ctx, bobChannelID)
}
