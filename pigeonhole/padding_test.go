// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/pigeonhole/geo"
)

func TestCreatePaddedPayload(t *testing.T) {
	t.Run("BasicPadding", func(t *testing.T) {
		message := []byte("Hello, World!")
		targetSize := 100

		paddedPayload, err := CreatePaddedPayload(message, targetSize)
		require.NoError(t, err)
		require.Equal(t, targetSize, len(paddedPayload))

		// Extract the message back
		extractedMessage, err := ExtractMessageFromPaddedPayload(paddedPayload)
		require.NoError(t, err)
		require.Equal(t, message, extractedMessage)
	})

	t.Run("MessageTooLarge", func(t *testing.T) {
		message := make([]byte, 100)
		targetSize := 50 // Too small for message + 4-byte prefix

		_, err := CreatePaddedPayload(message, targetSize)
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds target size")
	})

	t.Run("ExactFit", func(t *testing.T) {
		message := []byte("test")
		targetSize := 8 // 4 bytes for prefix + 4 bytes for message

		paddedPayload, err := CreatePaddedPayload(message, targetSize)
		require.NoError(t, err)
		require.Equal(t, targetSize, len(paddedPayload))

		extractedMessage, err := ExtractMessageFromPaddedPayload(paddedPayload)
		require.NoError(t, err)
		require.Equal(t, message, extractedMessage)
	})

	t.Run("EmptyMessage", func(t *testing.T) {
		message := []byte{}
		targetSize := 10

		paddedPayload, err := CreatePaddedPayload(message, targetSize)
		require.NoError(t, err)
		require.Equal(t, targetSize, len(paddedPayload))

		extractedMessage, err := ExtractMessageFromPaddedPayload(paddedPayload)
		require.NoError(t, err)
		require.Equal(t, message, extractedMessage)
	})

	t.Run("LengthPrefixValidation", func(t *testing.T) {
		message := []byte("test message")
		targetSize := 50

		paddedPayload, err := CreatePaddedPayload(message, targetSize)
		require.NoError(t, err)

		// Check that the length prefix is correct
		expectedLength := uint32(len(message))
		actualLength := uint32(paddedPayload[0])<<24 | uint32(paddedPayload[1])<<16 | uint32(paddedPayload[2])<<8 | uint32(paddedPayload[3])
		require.Equal(t, expectedLength, actualLength)

		// Check that the message is at the right position
		actualMessage := paddedPayload[4 : 4+len(message)]
		require.Equal(t, message, actualMessage)

		// Check that the rest is zero padding
		padding := paddedPayload[4+len(message):]
		for i, b := range padding {
			require.Equal(t, uint8(0), b, "padding byte %d should be zero", i)
		}
	})
}

func TestPadToSize(t *testing.T) {
	t.Run("pads short data", func(t *testing.T) {
		data := []byte("hello")
		padded, err := PadToSize(data, 10)
		require.NoError(t, err)
		require.Len(t, padded, 10)
		require.Equal(t, data, padded[:5])
		for i := 5; i < 10; i++ {
			require.Equal(t, byte(0), padded[i])
		}
	})

	t.Run("exact size is no-op", func(t *testing.T) {
		data := []byte("exact")
		padded, err := PadToSize(data, 5)
		require.NoError(t, err)
		require.Equal(t, data, padded)
	})

	t.Run("data too large returns error", func(t *testing.T) {
		data := []byte("too long")
		_, err := PadToSize(data, 3)
		require.ErrorIs(t, err, ErrPadDataExceedsTarget)
	})

	t.Run("empty data pads to target", func(t *testing.T) {
		padded, err := PadToSize([]byte{}, 8)
		require.NoError(t, err)
		require.Len(t, padded, 8)
	})

	t.Run("nil data pads to target", func(t *testing.T) {
		padded, err := PadToSize(nil, 8)
		require.NoError(t, err)
		require.Len(t, padded, 8)
	})
}

func TestReplicaInnerMessageWriteSize(t *testing.T) {
	nikeScheme := schemes.ByName("CTIDH1024-X25519")
	g := geo.NewGeometry(1000, nikeScheme)

	// Construct a real max-size write ReplicaInnerMessage
	bacapCiphertextLen := g.CalculateBoxCiphertextLength()
	write := &ReplicaInnerMessage{
		MessageType: 1,
		WriteMsg: &ReplicaWrite{
			BoxID:      [32]uint8{},
			Signature:  [64]uint8{},
			PayloadLen: uint32(bacapCiphertextLen),
			Payload:    make([]uint8, bacapCiphertextLen),
		},
	}
	actualSize := len(write.Bytes())
	require.Equal(t, g.ReplicaInnerMessageWriteSize(), actualSize,
		"geometry calculation must match actual serialized write size")

	// A read message must be smaller
	read := &ReplicaInnerMessage{
		MessageType: 0,
		ReadMsg: &ReplicaRead{
			BoxID: [32]uint8{},
		},
	}
	readSize := len(read.Bytes())
	require.Less(t, readSize, actualSize, "read should be smaller than write")

	// A tombstone (write with empty payload) must be smaller
	tombstone := &ReplicaInnerMessage{
		MessageType: 1,
		WriteMsg: &ReplicaWrite{
			BoxID:      [32]uint8{},
			Signature:  [64]uint8{},
			PayloadLen: 0,
			Payload:    nil,
		},
	}
	tombstoneSize := len(tombstone.Bytes())
	require.Less(t, tombstoneSize, actualSize, "tombstone should be smaller than write")
}

func TestReplicaReplyInnerMessageReadSize(t *testing.T) {
	nikeScheme := schemes.ByName("CTIDH1024-X25519")
	g := geo.NewGeometry(1000, nikeScheme)

	// Construct a real max-size read reply
	bacapCiphertextLen := g.CalculateBoxCiphertextLength()
	readReply := &ReplicaMessageReplyInnerMessage{
		MessageType: 0,
		ReadReply: &ReplicaReadReply{
			ErrorCode:  0,
			BoxID:      [32]uint8{},
			Signature:  [64]uint8{},
			PayloadLen: uint32(bacapCiphertextLen),
			Payload:    make([]uint8, bacapCiphertextLen),
		},
	}
	actualSize := len(readReply.Bytes())
	require.Equal(t, g.ReplicaReplyInnerMessageReadSize(), actualSize,
		"geometry calculation must match actual serialized read reply size")

	// A write reply must be smaller
	writeReply := &ReplicaMessageReplyInnerMessage{
		MessageType: 1,
		WriteReply: &ReplicaWriteReply{
			ErrorCode: 0,
		},
	}
	writeReplySize := len(writeReply.Bytes())
	require.Less(t, writeReplySize, actualSize, "write reply should be smaller than read reply")

	// A tombstone read reply (empty payload) must be smaller
	tombstoneReply := &ReplicaMessageReplyInnerMessage{
		MessageType: 0,
		ReadReply: &ReplicaReadReply{
			ErrorCode:  11, // ReplicaErrorTombstone
			BoxID:      [32]uint8{},
			Signature:  [64]uint8{},
			PayloadLen: 0,
			Payload:    nil,
		},
	}
	tombstoneReplySize := len(tombstoneReply.Bytes())
	require.Less(t, tombstoneReplySize, actualSize, "tombstone reply should be smaller than read reply")
}

// TestPadInnerMessageForEncryption verifies that the padding function produces
// equal-length output for tombstone writes and normal writes.
func TestPadInnerMessageForEncryption(t *testing.T) {
	nikeScheme := schemes.ByName("CTIDH1024-X25519")
	g := geo.NewGeometry(1000, nikeScheme)
	bacapCiphertextLen := g.CalculateBoxCiphertextLength()

	normalWrite := &ReplicaInnerMessage{
		MessageType: 1,
		WriteMsg: &ReplicaWrite{
			BoxID:      [32]uint8{1},
			Signature:  [64]uint8{2},
			PayloadLen: uint32(bacapCiphertextLen),
			Payload:    make([]uint8, bacapCiphertextLen),
		},
	}

	tombstoneWrite := &ReplicaInnerMessage{
		MessageType: 1,
		WriteMsg: &ReplicaWrite{
			BoxID:      [32]uint8{1},
			Signature:  [64]uint8{2},
			PayloadLen: 0,
			Payload:    nil,
		},
	}

	normalPadded, err := PadInnerMessageForEncryption(normalWrite, g)
	require.NoError(t, err)

	tombstonePadded, err := PadInnerMessageForEncryption(tombstoneWrite, g)
	require.NoError(t, err)

	require.Equal(t, len(normalPadded), len(tombstonePadded),
		"tombstone write and normal write must produce equal-length padded plaintext")
}

// TestPadReplyInnerMessageForEncryption verifies that the padding function produces
// equal-length output for tombstone read replies and normal read replies.
func TestPadReplyInnerMessageForEncryption(t *testing.T) {
	nikeScheme := schemes.ByName("CTIDH1024-X25519")
	g := geo.NewGeometry(1000, nikeScheme)
	bacapCiphertextLen := g.CalculateBoxCiphertextLength()

	normalReadReply := &ReplicaMessageReplyInnerMessage{
		MessageType: 0,
		ReadReply: &ReplicaReadReply{
			ErrorCode:  0,
			BoxID:      [32]uint8{1},
			Signature:  [64]uint8{2},
			PayloadLen: uint32(bacapCiphertextLen),
			Payload:    make([]uint8, bacapCiphertextLen),
		},
	}

	tombstoneReadReply := &ReplicaMessageReplyInnerMessage{
		MessageType: 0,
		ReadReply: &ReplicaReadReply{
			ErrorCode:  11,
			BoxID:      [32]uint8{1},
			Signature:  [64]uint8{2},
			PayloadLen: 0,
			Payload:    nil,
		},
	}

	normalPadded, err := PadReplyInnerMessageForEncryption(normalReadReply, g)
	require.NoError(t, err)

	tombstonePadded, err := PadReplyInnerMessageForEncryption(tombstoneReadReply, g)
	require.NoError(t, err)

	require.Equal(t, len(normalPadded), len(tombstonePadded),
		"tombstone read reply and normal read reply must produce equal-length padded plaintext")
}

// TestTombstoneWriteMKEMCiphertextIndistinguishable does full MKEM encryption
// and verifies that the ciphertext sizes are identical for tombstone vs normal write.
func TestTombstoneWriteMKEMCiphertextIndistinguishable(t *testing.T) {
	nikeScheme := schemes.ByName("CTIDH1024-X25519")
	mkemScheme := mkem.NewScheme(nikeScheme)
	g := geo.NewGeometry(1000, nikeScheme)
	bacapCiphertextLen := g.CalculateBoxCiphertextLength()

	// Generate replica keys
	replica0Pub, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replica1Pub, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replicaPubKeys := []nike.PublicKey{replica0Pub, replica1Pub}

	normalWrite := &ReplicaInnerMessage{
		MessageType: 1,
		WriteMsg: &ReplicaWrite{
			BoxID:      [32]uint8{1},
			Signature:  [64]uint8{2},
			PayloadLen: uint32(bacapCiphertextLen),
			Payload:    make([]uint8, bacapCiphertextLen),
		},
	}

	tombstoneWrite := &ReplicaInnerMessage{
		MessageType: 1,
		WriteMsg: &ReplicaWrite{
			BoxID:      [32]uint8{1},
			Signature:  [64]uint8{2},
			PayloadLen: 0,
			Payload:    nil,
		},
	}

	normalPadded, err := PadInnerMessageForEncryption(normalWrite, g)
	require.NoError(t, err)
	tombstonePadded, err := PadInnerMessageForEncryption(tombstoneWrite, g)
	require.NoError(t, err)

	_, normalCiphertext := mkemScheme.Encapsulate(replicaPubKeys, normalPadded)
	_, tombstoneCiphertext := mkemScheme.Encapsulate(replicaPubKeys, tombstonePadded)

	require.Equal(t, len(normalCiphertext.Envelope), len(tombstoneCiphertext.Envelope),
		"MKEM ciphertext must be identical size for tombstone and normal write")
}

// TestTombstoneReadReplyMKEMCiphertextIndistinguishable does full MKEM reply encryption
// and verifies that the ciphertext sizes are identical for tombstone vs normal read reply.
func TestTombstoneReadReplyMKEMCiphertextIndistinguishable(t *testing.T) {
	nikeScheme := schemes.ByName("CTIDH1024-X25519")
	mkemScheme := mkem.NewScheme(nikeScheme)
	g := geo.NewGeometry(1000, nikeScheme)
	bacapCiphertextLen := g.CalculateBoxCiphertextLength()

	// Generate keys for envelope reply
	_, replicaPriv, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	clientPub, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)

	normalReadReply := &ReplicaMessageReplyInnerMessage{
		MessageType: 0,
		ReadReply: &ReplicaReadReply{
			ErrorCode:  0,
			BoxID:      [32]uint8{1},
			Signature:  [64]uint8{2},
			PayloadLen: uint32(bacapCiphertextLen),
			Payload:    make([]uint8, bacapCiphertextLen),
		},
	}

	tombstoneReadReply := &ReplicaMessageReplyInnerMessage{
		MessageType: 0,
		ReadReply: &ReplicaReadReply{
			ErrorCode:  11,
			BoxID:      [32]uint8{1},
			Signature:  [64]uint8{2},
			PayloadLen: 0,
			Payload:    nil,
		},
	}

	normalPadded, err := PadReplyInnerMessageForEncryption(normalReadReply, g)
	require.NoError(t, err)
	tombstonePadded, err := PadReplyInnerMessageForEncryption(tombstoneReadReply, g)
	require.NoError(t, err)

	normalReply := mkemScheme.EnvelopeReply(replicaPriv, clientPub, normalPadded)
	tombstoneReply := mkemScheme.EnvelopeReply(replicaPriv, clientPub, tombstonePadded)

	require.Equal(t, len(normalReply.Envelope), len(tombstoneReply.Envelope),
		"MKEM reply ciphertext must be identical size for tombstone and normal read reply")
}

// TestReadWriteQueryMKEMCiphertextIndistinguishable verifies that read and write
// queries produce identical MKEM ciphertext sizes after padding.
func TestReadWriteQueryMKEMCiphertextIndistinguishable(t *testing.T) {
	nikeScheme := schemes.ByName("CTIDH1024-X25519")
	mkemScheme := mkem.NewScheme(nikeScheme)
	g := geo.NewGeometry(1000, nikeScheme)
	bacapCiphertextLen := g.CalculateBoxCiphertextLength()

	replica0Pub, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replica1Pub, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replicaPubKeys := []nike.PublicKey{replica0Pub, replica1Pub}

	readQuery := &ReplicaInnerMessage{
		MessageType: 0,
		ReadMsg: &ReplicaRead{
			BoxID: [32]uint8{1},
		},
	}

	writeQuery := &ReplicaInnerMessage{
		MessageType: 1,
		WriteMsg: &ReplicaWrite{
			BoxID:      [32]uint8{1},
			Signature:  [64]uint8{2},
			PayloadLen: uint32(bacapCiphertextLen),
			Payload:    make([]uint8, bacapCiphertextLen),
		},
	}

	readPadded, err := PadInnerMessageForEncryption(readQuery, g)
	require.NoError(t, err)
	writePadded, err := PadInnerMessageForEncryption(writeQuery, g)
	require.NoError(t, err)

	_, readCiphertext := mkemScheme.Encapsulate(replicaPubKeys, readPadded)
	_, writeCiphertext := mkemScheme.Encapsulate(replicaPubKeys, writePadded)

	require.Equal(t, len(readCiphertext.Envelope), len(writeCiphertext.Envelope),
		"MKEM ciphertext must be identical size for read and write queries")
}

// TestReadWriteReplyMKEMCiphertextIndistinguishable verifies that read and write
// reply messages produce identical MKEM envelope reply sizes after padding.
func TestReadWriteReplyMKEMCiphertextIndistinguishable(t *testing.T) {
	nikeScheme := schemes.ByName("CTIDH1024-X25519")
	mkemScheme := mkem.NewScheme(nikeScheme)
	g := geo.NewGeometry(1000, nikeScheme)
	bacapCiphertextLen := g.CalculateBoxCiphertextLength()

	_, replicaPriv, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	clientPub, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)

	readReply := &ReplicaMessageReplyInnerMessage{
		MessageType: 0,
		ReadReply: &ReplicaReadReply{
			ErrorCode:  0,
			BoxID:      [32]uint8{1},
			Signature:  [64]uint8{2},
			PayloadLen: uint32(bacapCiphertextLen),
			Payload:    make([]uint8, bacapCiphertextLen),
		},
	}

	writeReply := &ReplicaMessageReplyInnerMessage{
		MessageType: 1,
		WriteReply:  &ReplicaWriteReply{ErrorCode: 0},
	}

	readPadded, err := PadReplyInnerMessageForEncryption(readReply, g)
	require.NoError(t, err)
	writePadded, err := PadReplyInnerMessageForEncryption(writeReply, g)
	require.NoError(t, err)

	readEnvReply := mkemScheme.EnvelopeReply(replicaPriv, clientPub, readPadded)
	writeEnvReply := mkemScheme.EnvelopeReply(replicaPriv, clientPub, writePadded)

	require.Equal(t, len(readEnvReply.Envelope), len(writeEnvReply.Envelope),
		"MKEM reply ciphertext must be identical size for read and write replies")
}

func TestExtractMessageFromPaddedPayload(t *testing.T) {
	t.Run("InvalidLength", func(t *testing.T) {
		// Too short for length prefix
		shortPayload := []byte{1, 2}
		_, err := ExtractMessageFromPaddedPayload(shortPayload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "too short")
	})

	t.Run("InvalidMessageLength", func(t *testing.T) {
		// Length prefix says 100 bytes but payload only has 10
		invalidPayload := []byte{0, 0, 0, 100, 1, 2, 3, 4, 5, 6}
		_, err := ExtractMessageFromPaddedPayload(invalidPayload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid message length")
	})
}
