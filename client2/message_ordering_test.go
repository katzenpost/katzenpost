//go:build docker_test

// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client2/thin"
)

// TestMessageOrderingWithoutConfirm demonstrates the message ordering bug where
// the second message overwrites the first because StatefulWriter state
// is not advanced after courier ACK. It is expected to fail until we fix the code.
//
//  1. Alice writes "message_1" -> PrepareNext() uses sequence index N
//  2. Courier ACKs but AdvanceState() is never called
//  3. Alice writes "message_2" -> PrepareNext() uses sequence index N AGAIN
//  4. "message_2" overwrites "message_1" at the same BoxID
//  5. Bob reads and gets "message_2" instead of "message_1"
//
// go test -tags=docker_test -run TestMessageOrderingWithoutConfirm -v
func TestMessageOrderingWithoutConfirm(t *testing.T) {
	aliceThinClient := setupThinClient(t)
	defer aliceThinClient.Close()
	bobThinClient := setupThinClient(t)
	defer bobThinClient.Close()

	currentDoc := validatePKIDocument(t, aliceThinClient)
	currentEpoch := currentDoc.Epoch
	bobDoc := validatePKIDocument(t, bobThinClient)
	require.Equal(t, currentEpoch, bobDoc.Epoch, "Alice and Bob must use same PKI epoch")
	t.Logf("Using PKI document for epoch %d", currentEpoch)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	t.Log("Alice: Creating write channel")
	aliceChannelID, readCap, _, err := aliceThinClient.CreateWriteChannel(ctx)
	require.NoError(t, err)
	t.Logf("Alice: Created write channel %d", aliceChannelID)

	t.Log("Bob: Creating read channel")
	bobChannelID, err := bobThinClient.CreateReadChannel(ctx, readCap)
	require.NoError(t, err)
	t.Logf("Bob: Created read channel %d", bobChannelID)

	message1 := []byte("message_1_FIRST")
	message2 := []byte("message_2_SECOND")

	t.Log("Alice: Writing first message 'message_1_FIRST'")
	writeReply1, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, message1)
	require.NoError(t, err)
	require.Equal(t, writeReply1.ErrorCode, thin.ThinClientSuccess, "Alice: First write operation failed")

	destNode, destQueue, err := aliceThinClient.GetCourierDestination()
	require.NoError(t, err)
	messageID1 := aliceThinClient.NewMessageID()
	_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, writeReply1.SendMessagePayload, destNode, destQueue, messageID1)
	require.NoError(t, err)
	t.Log("Alice: First message sent and ACK received")
	t.Log("Alice: Writing second message 'message_2_SECOND'")
	writeReply2, err := aliceThinClient.WriteChannel(ctx, aliceChannelID, message2)
	require.NoError(t, err)
	require.Equal(t, writeReply2.ErrorCode, thin.ThinClientSuccess, "Alice: Second write operation failed")
	messageID2 := aliceThinClient.NewMessageID()
	_, err = aliceThinClient.SendChannelQueryAwaitReply(ctx, aliceChannelID, writeReply2.SendMessagePayload, destNode, destQueue, messageID2)
	require.NoError(t, err)
	t.Log("Alice: Second message sent and ACK received")
	t.Log("Waiting for message propagation to storage replicas")
	time.Sleep(10 * time.Second)
	t.Log("Bob: Reading first message (expecting 'message_1_FIRST')")
	readReply1, err := bobThinClient.ReadChannel(ctx, bobChannelID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, readReply1.ErrorCode, thin.ThinClientSuccess, "Bob: First read operation failed")
	bobMessageID1 := bobThinClient.NewMessageID()
	var bobPayload1 []byte

	for i := 0; i < 10; i++ {
		bobPayload1, err = bobThinClient.SendChannelQueryAwaitReply(ctx, bobChannelID, readReply1.SendMessagePayload, destNode, destQueue, bobMessageID1)
		require.NoError(t, err)
		if len(bobPayload1) > 0 {
			break
		}
		t.Logf("Bob: Retry %d for first message", i+1)
		time.Sleep(1 * time.Second)
	}

	t.Logf("Bob: Received first message: %q (expected: %q)", string(bobPayload1), string(message1))

	require.Equal(t, message1, bobPayload1,
		"First message read was %q but expected %q. "+
			"This proves the message ordering bug where the second message "+
			"overwrites the first due to StatefulWriter state not being advanced.",
		string(bobPayload1), string(message1))

	aliceThinClient.CloseChannel(ctx, aliceChannelID)
	bobThinClient.CloseChannel(ctx, bobChannelID)

	t.Log("SUCCESS: Message ordering is correct!")
}
