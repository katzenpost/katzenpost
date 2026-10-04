// SPDX-FileCopyrightText: © 2025 Katzenpost dev team
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
	"github.com/stretchr/testify/require"
)

const testContext = "PIGEONHOLE_CTX"

// TestBACAPSequenceOverwrite tests how to write a BACAP sequence and then overwrite it with tombstones
func TestBACAPSequenceOverwrite(t *testing.T) {
	ctx := []byte(testContext)

	// Create a WriteCap (this is like Alice's write capability)
	owner, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)

	// Write the original sequence from the cap's own index
	idx := owner.GetMessageBoxIndex()

	// Write some messages to the sequence
	messages := [][]byte{
		[]byte("Hello, World!"),
		[]byte("This is message 2"),
		[]byte("Final message"),
	}

	var originalBoxes []struct {
		BoxID      [bacap.BoxIDSize]byte
		Ciphertext []byte
		Signature  []byte
	}

	t.Log("Writing original messages to sequence...")
	for i, msg := range messages {
		boxID, ciphertext, sig, err := idx.EncryptForContext(owner, ctx, msg)
		require.NoError(t, err)
		idx, err = idx.NextIndex()
		require.NoError(t, err)

		originalBoxes = append(originalBoxes, struct {
			BoxID      [bacap.BoxIDSize]byte
			Ciphertext []byte
			Signature  []byte
		}{
			BoxID:      boxID,
			Ciphertext: ciphertext,
			Signature:  sig,
		})

		t.Logf("Wrote message %d to BoxID %x", i+1, boxID[:8])
	}

	// Now verify we can read the original messages
	t.Log("Verifying original messages can be read...")
	readCap := owner.ReadCap()
	readIdx := readCap.GetMessageBoxIndex()

	for i, originalBox := range originalBoxes {
		// Get the expected BoxID
		expectedBoxID, err := readIdx.BoxIDForContext(readCap, ctx)
		require.NoError(t, err)
		require.Equal(t, expectedBoxID.Bytes(), originalBox.BoxID[:], "BoxID should match")

		// Decrypt the message
		readPos, err := readCap.PositionAt(readIdx)
		require.NoError(t, err)
		plaintext, err := readPos.Open(ctx, originalBox.BoxID, originalBox.Ciphertext, originalBox.Signature)
		require.NoError(t, err)
		readIdx, err = readIdx.NextIndex()
		require.NoError(t, err)
		require.Equal(t, messages[i], plaintext, "Decrypted message should match original")

		t.Logf("Successfully read message %d: %s", i+1, string(plaintext))
	}

	// Now let's figure out how to overwrite with tombstones
	t.Log("Now attempting to overwrite with tombstones...")

	// The key question: does walking again from the same WriteCap's index
	// generate the same BoxIDs?
	tombstoneIdx := owner.GetMessageBoxIndex()

	tombstonePayload := make([]byte, 100) // All zeros

	for i := 0; i < len(originalBoxes); i++ {
		// Get the next BoxID from the tombstone writer
		tombstoneBoxID, tombstoneCiphertext, tombstoneSig, err := tombstoneIdx.EncryptForContext(owner, ctx, tombstonePayload)
		require.NoError(t, err)
		tombstoneIdx, err = tombstoneIdx.NextIndex()
		require.NoError(t, err)

		t.Logf("Tombstone %d: BoxID %x (original was %x)", i+1, tombstoneBoxID[:8], originalBoxes[i].BoxID[:8])

		// Check if the BoxIDs match
		if tombstoneBoxID == originalBoxes[i].BoxID {
			t.Logf("SUCCESS: Tombstone BoxID matches original BoxID for message %d", i+1)
		} else {
			t.Logf("MISMATCH: Tombstone BoxID %x != original BoxID %x for message %d",
				tombstoneBoxID[:8], originalBoxes[i].BoxID[:8], i+1)
		}

		// Store the tombstone for verification
		originalBoxes[i].Ciphertext = tombstoneCiphertext
		originalBoxes[i].Signature = tombstoneSig
	}

	// Now verify that reading the sequence gives us tombstones (all zeros)
	t.Log("Verifying tombstones can be read...")
	tombstoneReadIdx := readCap.GetMessageBoxIndex()

	for i := 0; i < len(originalBoxes); i++ {
		expectedBoxID, err := tombstoneReadIdx.BoxIDForContext(readCap, ctx)
		require.NoError(t, err)
		require.Equal(t, expectedBoxID.Bytes(), originalBoxes[i].BoxID[:], "BoxID should still match")

		readPos, err := readCap.PositionAt(tombstoneReadIdx)

		require.NoError(t, err)

		plaintext, err := readPos.Open(ctx, originalBoxes[i].BoxID, originalBoxes[i].Ciphertext, originalBoxes[i].Signature)
		require.NoError(t, err)
		tombstoneReadIdx, err = tombstoneReadIdx.NextIndex()
		require.NoError(t, err)

		// Verify it's all zeros (tombstone)
		expectedTombstone := make([]byte, 100)
		require.Equal(t, expectedTombstone, plaintext, "Tombstone should be all zeros")

		t.Logf("Successfully verified tombstone %d: %d bytes of zeros", i+1, len(plaintext))
	}

	t.Log("SUCCESS: BACAP sequence overwrite with tombstones works!")
}

// TestBACAPBoxIDDeterminism tests whether BoxIDs are deterministic
func TestBACAPBoxIDDeterminism(t *testing.T) {
	ctx := []byte(testContext)

	// Create a WriteCap
	owner, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)

	// Walk twice from the same WriteCap's index
	idx1 := owner.GetMessageBoxIndex()
	idx2 := owner.GetMessageBoxIndex()

	// Write the same number of messages with both writers
	numMessages := 5

	for i := 0; i < numMessages; i++ {
		msg := []byte("test message")

		boxID1, _, _, err := idx1.EncryptForContext(owner, ctx, msg)
		require.NoError(t, err)
		idx1, err = idx1.NextIndex()
		require.NoError(t, err)

		boxID2, _, _, err := idx2.EncryptForContext(owner, ctx, msg)
		require.NoError(t, err)
		idx2, err = idx2.NextIndex()
		require.NoError(t, err)

		t.Logf("Message %d: Writer1 BoxID %x, Writer2 BoxID %x", i+1, boxID1[:8], boxID2[:8])

		if boxID1 == boxID2 {
			t.Logf("✓ BoxIDs match for message %d", i+1)
		} else {
			t.Logf("✗ BoxIDs differ for message %d", i+1)
		}

		require.Equal(t, boxID1, boxID2, "BoxIDs should be deterministic")
	}

	t.Log("SUCCESS: BACAP BoxIDs are deterministic!")
}
