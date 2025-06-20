// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"encoding/binary"
	"fmt"
	"reflect"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/nike"
)

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

// CreatePaddedPayload creates a padded payload with a 4-byte length prefix.
// This implements the pigeonhole protocol's 4-byte length prefix padding scheme
// inside box payload plaintext. The geometry object tracks overhead across
// nested layers of encapsulation/encoding/encryption.
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

// CreateWriteEnvelope creates a CourierEnvelope for write operations
// This function encapsulates the common pattern of creating write envelopes
func CreateWriteEnvelope(
	boxID [32]uint8,
	signature [64]uint8,
	payload []byte,
	replicaPubKeys []nike.PublicKey,
	intermediateReplicas [2]uint8,
	epoch uint64,
	mkemScheme interface{},
) (*CourierEnvelope, nike.PrivateKey, error) {

	writeRequest := &ReplicaWrite{
		BoxID:      boxID,
		Signature:  signature,
		PayloadLen: uint32(len(payload)),
		Payload:    payload,
	}

	msg := &ReplicaInnerMessage{
		MessageType: 1, // 1 = write
		WriteMsg:    writeRequest,
	}

	return createEnvelopeFromMessage(msg, replicaPubKeys, intermediateReplicas, epoch, mkemScheme, false)
}

// CreateReadEnvelope creates a CourierEnvelope for read operations
// This function encapsulates the common pattern of creating read envelopes
func CreateReadEnvelope(
	boxID [32]uint8,
	replicaPubKeys []nike.PublicKey,
	intermediateReplicas [2]uint8,
	epoch uint64,
	mkemScheme interface{},
) (*CourierEnvelope, nike.PrivateKey, error) {

	msg := &ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg: &ReplicaRead{
			BoxID: boxID,
		},
	}

	return createEnvelopeFromMessage(msg, replicaPubKeys, intermediateReplicas, epoch, mkemScheme, true)
}

// createEnvelopeFromMessage is the shared implementation for envelope creation
func createEnvelopeFromMessage(
	msg *ReplicaInnerMessage,
	replicaPubKeys []nike.PublicKey,
	intermediateReplicas [2]uint8,
	epoch uint64,
	mkemScheme interface{},
	isRead bool,
) (*CourierEnvelope, nike.PrivateKey, error) {
 // Define interface or use type assertion instead of reflection
 type MKEMScheme interface {
     Encapsulate(keys []nike.PublicKey, payload []byte) (nike.PrivateKey, interface{})
 }

 scheme, ok := mkemScheme.(MKEMScheme)
 if !ok {
     return nil, nil, fmt.Errorf("mkemScheme does not implement required interface")
 }

 mkemPrivateKey, ciphertext := scheme.Encapsulate(replicaPubKeys, msg.Bytes())
	if len(results) != 2 {
		return nil, nil, fmt.Errorf("Encapsulate method returned unexpected number of values")
	}

 mkemPrivateKey, ok := results[0].Interface().(nike.PrivateKey)
 if !ok {
     return nil, nil, fmt.Errorf("failed to cast result to nike.PrivateKey")
 }
 mkemPublicKey := mkemPrivateKey.Public()

 // Extract DEKCiphertexts and Envelope from the ciphertext using reflection
 ciphertextValue := results[1]
 if ciphertextValue.Kind() == reflect.Ptr {
     ciphertextValue = ciphertextValue.Elem()
 }

 dekCiphertextsField := ciphertextValue.FieldByName("DEKCiphertexts")
 envelopeField := ciphertextValue.FieldByName("Envelope")

 if !dekCiphertextsField.IsValid() || !envelopeField.IsValid() {
     return nil, nil, fmt.Errorf("MKEM ciphertext does not have expected DEKCiphertexts and Envelope fields")
 }

 dekCiphertexts, ok := dekCiphertextsField.Interface().([]*[60]byte)
 if !ok {
     return nil, nil, fmt.Errorf("failed to cast DEKCiphertexts to expected type")
 }
 envelope, ok := envelopeField.Interface().([]byte)
 if !ok {
     return nil, nil, fmt.Errorf("failed to cast Envelope to []byte")
 }

	var dek1, dek2 [60]uint8
	copy(dek1[:], dekCiphertexts[0][:])
	copy(dek2[:], dekCiphertexts[1][:])

	senderPubkeyBytes := mkemPublicKey.Bytes()

	var isReadUint8 uint8
	if isRead {
		isReadUint8 = 1
	} else {
		isReadUint8 = 0
	}

	courierEnvelope := &CourierEnvelope{
		IntermediateReplicas: intermediateReplicas,
		Dek1:                 dek1,
		Dek2:                 dek2,
		ReplyIndex:           0,
		Epoch:                epoch,
		SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
		SenderPubkey:         senderPubkeyBytes,
		CiphertextLen:        uint32(len(envelope)),
		Ciphertext:           envelope,
		IsRead:               isReadUint8,
	}

	return courierEnvelope, mkemPrivateKey, nil
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
