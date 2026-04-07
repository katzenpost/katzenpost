// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/hash"

	pgeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

// ErrPadDataExceedsTarget is returned when data is larger than the target padding size.
var ErrPadDataExceedsTarget = errors.New("data exceeds target size")

// ErrNilGeometry is returned when a nil geometry is passed to a padding function.
var ErrNilGeometry = errors.New("pigeonhole geometry is nil")

// PadToSize pads data with trailing zeros to reach targetSize.
// Returns the data unchanged if already the target size.
func PadToSize(data []byte, targetSize int) ([]byte, error) {
	if len(data) > targetSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrPadDataExceedsTarget, len(data), targetSize)
	}
	if len(data) == targetSize {
		return data, nil
	}
	return append(data, make([]byte, targetSize-len(data))...), nil
}

// PadInnerMessageForEncryption serializes a ReplicaInnerMessage and pads it
// to the write size so that tombstones are indistinguishable from normal writes.
func PadInnerMessageForEncryption(msg *ReplicaInnerMessage, geo *pgeo.Geometry) ([]byte, error) {
	if geo == nil {
		return nil, ErrNilGeometry
	}
	return PadToSize(msg.Bytes(), geo.ReplicaInnerMessageWriteSize())
}

// PadReplyInnerMessageForEncryption serializes a ReplicaMessageReplyInnerMessage
// and pads it to the read reply size so that tombstone read replies are
// indistinguishable from normal read replies.
func PadReplyInnerMessageForEncryption(msg *ReplicaMessageReplyInnerMessage, geo *pgeo.Geometry) ([]byte, error) {
	if geo == nil {
		return nil, ErrNilGeometry
	}
	return PadToSize(msg.Bytes(), geo.ReplicaReplyInnerMessageReadSize())
}

// Helper functions for backward compatibility with the old methods.go file

// EnvelopeHash returns the hash of the CourierEnvelope.
func (c *CourierEnvelope) EnvelopeHash() *[hash.HashSize]byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, err = h.Write(c.SenderPubkey)
	if err != nil {
		panic(err)
	}
	_, err = h.Write(c.Ciphertext)
	if err != nil {
		panic(err)
	}
	s := h.Sum([]byte{})
	hashOut := &[hash.HashSize]byte{}
	copy(hashOut[:], s)
	return hashOut
}

func CreatePaddedPayload(message []byte, targetSize int) ([]byte, error) {
	// 4-byte length prefix + message data
	const lengthPrefixSize = 4

	if len(message) > targetSize-lengthPrefixSize {
		return nil, fmt.Errorf("message size %d exceeds target size %d (accounting for %d-byte length prefix)",
			len(message), targetSize, lengthPrefixSize)
	}

	// Create padded payload: [4-byte length][message][padding]
	paddedPayload := make([]byte, targetSize)

	// Write the length prefix (big-endian)
	binary.BigEndian.PutUint32(paddedPayload[0:4], uint32(len(message)))

	// Copy the message data
	copy(paddedPayload[4:4+len(message)], message)

	// The rest is zero padding (already initialized to zero by make())
	return paddedPayload, nil
}

// ExtractMessageFromPaddedPayload extracts the original message from a padded payload
// created by CreatePaddedPayload.
func ExtractMessageFromPaddedPayload(paddedPayload []byte) ([]byte, error) {
	const lengthPrefixSize = 4

	if len(paddedPayload) < lengthPrefixSize {
		return nil, fmt.Errorf("padded payload too short: %d bytes, need at least %d",
			len(paddedPayload), lengthPrefixSize)
	}

	// Read the length prefix
	messageLength := binary.BigEndian.Uint32(paddedPayload[0:4])

	if int(messageLength) > len(paddedPayload)-lengthPrefixSize {
		return nil, fmt.Errorf("invalid message length %d, padded payload only has %d bytes after prefix",
			messageLength, len(paddedPayload)-lengthPrefixSize)
	}

	// Extract the message
	message := make([]byte, messageLength)
	copy(message, paddedPayload[4:4+messageLength])

	return message, nil
}

// CourierQueryFromBytes parses a CourierQuery from bytes
func CourierQueryFromBytes(data []byte) (*CourierQuery, error) {
	return ParseCourierQuery(data)
}

// BoxFromBytes parses a Box from bytes
func BoxFromBytes(data []byte) (*Box, error) {
	return ParseBox(data)
}

// Note: ErrorCode field is now directly available in the generated trunnel struct

// Bytes returns the marshaled binary representation (for backward compatibility)
func (c *CourierEnvelope) Bytes() []byte {
	data, _ := c.MarshalBinary()
	return data
}

// Bytes returns the marshaled binary representation (for backward compatibility)
func (c *CourierEnvelopeReply) Bytes() []byte {
	data, _ := c.MarshalBinary()
	return data
}

// Bytes returns the marshaled binary representation (for backward compatibility)
func (c *CourierQuery) Bytes() []byte {
	data, _ := c.MarshalBinary()
	return data
}

// Bytes returns the marshaled binary representation (for backward compatibility)
func (c *CourierQueryReply) Bytes() []byte {
	data, _ := c.MarshalBinary()
	return data
}

// Bytes returns the marshaled binary representation (for backward compatibility)
func (r *ReplicaRead) Bytes() []byte {
	data, _ := r.MarshalBinary()
	return data
}

// Bytes returns the marshaled binary representation (for backward compatibility)
func (r *ReplicaReadReply) Bytes() []byte {
	data, _ := r.MarshalBinary()
	return data
}

// Bytes returns the marshaled binary representation (for backward compatibility)
func (r *ReplicaWrite) Bytes() []byte {
	data, _ := r.MarshalBinary()
	return data
}

// Bytes returns the marshaled binary representation (for backward compatibility)
func (r *ReplicaWriteReply) Bytes() []byte {
	data, _ := r.MarshalBinary()
	return data
}

// Bytes returns the marshaled binary representation (for backward compatibility)
func (r *ReplicaInnerMessage) Bytes() []byte {
	data, _ := r.MarshalBinary()
	return data
}

// Bytes returns the marshaled binary representation (for backward compatibility)
func (r *ReplicaMessageReplyInnerMessage) Bytes() []byte {
	data, _ := r.MarshalBinary()
	return data
}

// Bytes returns the marshaled binary representation (for backward compatibility)
func (b *Box) Bytes() []byte {
	data, _ := b.MarshalBinary()
	return data
}
