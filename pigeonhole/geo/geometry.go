// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package geo

import (
	"errors"
	"fmt"

	"github.com/katzenpost/chacha20poly1305"
	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// Geometry is a "pigeonhole geometry" object which provides mathematically
// precise geometry calculations using trunnel's fixed binary format.
//
// It supports 3 distinct use cases:
// 1. Given MaxPlaintextPayloadLength → compute a Pigeonhole Geometry which can derive all envelope sizes
// 2. Given precomputed Pigeonhole Geometry → derive accommodating Sphinx Geometry
// 3. Given Sphinx Geometry constraint → derive optimal Pigeonhole Geometry
type Geometry struct {
	// MaxPlaintextPayloadLength is the maximum usable plaintext payload size within a Box
	MaxPlaintextPayloadLength int

	// CourierQueryReadLength is the size of a CourierQuery containing a ReplicaRead
	CourierQueryReadLength int

	// CourierQueryWriteLength is the size of a CourierQuery containing a ReplicaWrite
	CourierQueryWriteLength int

	// CourierQueryReplyReadLength is the size of a CourierQueryReply containing a ReplicaReadReply
	CourierQueryReplyReadLength int

	// CourierQueryReplyWriteLength is the size of a CourierQueryReply containing a ReplicaWriteReply
	CourierQueryReplyWriteLength int

	// NIKEName specifies the NIKE scheme to be used in our MKEM scheme for encrypting
	// to multiple storage replicas
	NIKEName string

	// SignatureSchemeName specifies the signature scheme used for BACAP
	SignatureSchemeName string
}

const (
	// BACAP encryption overhead
	bacapEncryptionOverhead = 16

	// Length prefix for padded payloads
	lengthPrefixSize = 4

	// MKEM encryption overhead (ChaCha20-Poly1305)
	mkemEncryptionOverhead = chacha20poly1305.NonceSize + chacha20poly1305.Overhead

	// Signature scheme (always Ed25519 for BACAP)
	signatureSchemeName = "Ed25519"

	// Message type field size
	messageTypeSize = 1

	// Error code field size
	errorCodeFieldSize = 1

	// Success field size
	successFieldSize = 1

	// PayloadLen field size
	payloadLenFieldSize = 4

	// WriteReplyLen field size
	writeReplyLenFieldSize = 4

	// Minimal reply size for "OK"
	minimalOkReplySize = 2

	// ErrorLen field size
	errorLenFieldSize = 2

	// CourierEnvelopeReply field sizes
	timestampFieldSize     = 8 // uint64
	ciphertextLenFieldSize = 4 // uint32

	// CourierEnvelope field sizes
	intermediateReplicasSize = 2 // [2]uint8
	replyIndexSize           = 1 // uint8
	epochSize                = 8 // uint64
	senderPubkeyLenSize      = 2 // uint16

	// CourierQuery field sizes
	queryTypeSize = 1 // uint8 discriminator
)

// replicaWriteFixedOverhead calculates the fixed overhead for ReplicaWrite using actual BACAP sizes
func replicaWriteFixedOverhead() int {
	return bacap.BoxIDSize + bacap.SignatureSize + payloadLenFieldSize // BoxID + Signature + PayloadLen
}

// calculateCourierEnvelopeOverhead dynamically calculates the overhead for CourierEnvelope
func calculateCourierEnvelopeOverhead(_ int, senderPubkeySize int) int {
	// CourierEnvelope fixed fields from trunnel definition
	courierEnvelopeFixedOverhead := intermediateReplicasSize + mkem.DEKSize + mkem.DEKSize +
		replyIndexSize + epochSize + senderPubkeyLenSize + ciphertextLenFieldSize

	return courierEnvelopeFixedOverhead + senderPubkeySize
}

// calculateCourierQueryWrapperOverhead dynamically calculates the overhead for CourierQuery wrapper
func calculateCourierQueryWrapperOverhead(_ int, _ nike.Scheme) int {
	// CourierQuery union fields from trunnel serialization:
	// QueryType: uint8 = 1 byte (union discriminator)
	// Envelope: *CourierEnvelope (embedded struct, no length prefix)
	// CopyCommand: *CopyCommand (mutually exclusive with Envelope)
	return queryTypeSize
}

// NewGeometry creates a Geometry from MaxPlaintextPayloadLength (Use Case 1)
//
// This is the most common use case: given a desired payload size, calculate
// all the envelope sizes with mathematical precision using trunnel's fixed format.
func NewGeometry(boxPayloadLength int, nikeScheme nike.Scheme) *Geometry {
	g := &Geometry{
		MaxPlaintextPayloadLength: boxPayloadLength,
		NIKEName:                  nikeScheme.Name(),
		SignatureSchemeName:       signatureSchemeName,
	}

	// Calculate all envelope sizes with perfect precision!
	g.CourierQueryReadLength = g.calculateCourierQueryReadLength()
	g.CourierQueryWriteLength = g.calculateCourierQueryWriteLength()
	g.CourierQueryReplyReadLength = g.calculateCourierQueryReplyReadLength()
	g.CourierQueryReplyWriteLength = g.calculateCourierQueryReplyWriteLength()

	return g
}

// NewGeometryFromSphinx creates a Geometry from Sphinx constraints (Use Case 3)
//
// Given a Sphinx geometry with limited UserForwardPayloadLength, find the optimal
// MaxPlaintextPayloadLength that maximizes usage of the available space by directly calculating
// the overhead layers and subtracting them from the target size.
func NewGeometryFromSphinx(sphinxGeo *geo.Geometry, nikeScheme nike.Scheme) (*Geometry, error) {
	targetSize := sphinxGeo.UserForwardPayloadLength

	// Calculate all overhead layers for CourierQueryWrite (the largest envelope type)
	// Working backwards from CourierQuery to MaxPlaintextPayloadLength:

	// 1. CourierQuery wrapper overhead
	courierQueryOverhead := queryTypeSize // QueryType discriminator

	// 2. CourierEnvelope overhead (fixed fields + sender pubkey)
	senderPubkeySize := nikeScheme.PublicKeySize()
	courierEnvelopeOverhead := calculateCourierEnvelopeOverhead(0, senderPubkeySize) // Pass 0 for ciphertext size since we're calculating overhead

	// 3. MKEM encryption overhead
	mkemOverhead := mkemEncryptionOverhead

	// 4. ReplicaInnerMessage overhead
	replicaInnerMessageOverhead := messageTypeSize

	// 5. ReplicaWrite fixed overhead
	replicaWriteOverhead := replicaWriteFixedOverhead()

	// 6. BACAP encryption overhead
	bacapOverhead := bacapEncryptionOverhead

	// 7. Length prefix overhead for padded payloads
	lengthPrefixOverhead := lengthPrefixSize

	// Calculate total overhead
	totalOverhead := courierQueryOverhead + courierEnvelopeOverhead + mkemOverhead +
		replicaInnerMessageOverhead + replicaWriteOverhead + bacapOverhead + lengthPrefixOverhead

	// Calculate the MaxPlaintextPayloadLength by subtracting all overheads from target
	boxPayloadLength := targetSize - totalOverhead

	if boxPayloadLength <= 0 {
		return nil, fmt.Errorf("sphinx geometry too small: UserForwardPayloadLength=%d, total overhead=%d",
			targetSize, totalOverhead)
	}

	return NewGeometry(boxPayloadLength, nikeScheme), nil
}

// ToSphinxGeometry creates an accommodating Sphinx Geometry (Use Case 2)
//
// Given a precomputed Geometry, derive a Sphinx geometry that can
// accommodate the largest envelope size.
func (g *Geometry) ToSphinxGeometry(nrHops int, withSURB bool) *geo.Geometry {
	nikeScheme := g.NIKEScheme()

	// Find the maximum envelope size we need to accommodate
	maxEnvelopeSize := maxInt(
		g.CourierQueryReadLength,
		g.CourierQueryWriteLength,
		g.CourierQueryReplyReadLength,
		g.CourierQueryReplyWriteLength,
	)

	// Create Sphinx geometry that can handle our largest envelope
	return geo.GeometryFromUserForwardPayloadLength(nikeScheme, maxEnvelopeSize, withSURB, nrHops)
}

// Helper function for max of multiple values
func maxInt(values ...int) int {
	if len(values) == 0 {
		return 0
	}
	maxVal := values[0]
	for _, v := range values[1:] {
		if v > maxVal {
			maxVal = v
		}
	}
	return maxVal
}

// NIKEScheme returns the NIKE scheme used by this geometry
func (g *Geometry) NIKEScheme() nike.Scheme {
	scheme := schemes.ByName(g.NIKEName)
	if scheme == nil {
		panic(fmt.Sprintf("unknown NIKE scheme: %s", g.NIKEName))
	}
	return scheme
}

// Validate ensures the geometry is valid
func (g *Geometry) Validate() error {
	if g == nil {
		return errors.New("geometry is nil")
	}
	if g.MaxPlaintextPayloadLength <= 0 {
		return errors.New("MaxPlaintextPayloadLength must be positive")
	}
	if g.NIKEName == "" {
		return errors.New("NIKEName must be set")
	}
	if g.NIKEScheme() == nil {
		return fmt.Errorf("invalid NIKE scheme: %s", g.NIKEName)
	}
	if g.SignatureSchemeName != signatureSchemeName {
		return fmt.Errorf("SignatureSchemeName must be %s", signatureSchemeName)
	}
	return nil
}

// PaddedPayloadLength returns the payload size after adding length prefix
func (g *Geometry) PaddedPayloadLength() int {
	return g.MaxPlaintextPayloadLength + lengthPrefixSize
}

// String returns a human-readable representation
func (g *Geometry) String() string {
	return fmt.Sprintf(`Geometry:
  MaxPlaintextPayloadLength: %d bytes
  CourierQueryReadLength: %d bytes
  CourierQueryWriteLength: %d bytes
  CourierQueryReplyReadLength: %d bytes
  CourierQueryReplyWriteLength: %d bytes
  NIKEName: %s
  SignatureSchemeName: %s`,
		g.MaxPlaintextPayloadLength,
		g.CourierQueryReadLength,
		g.CourierQueryWriteLength,
		g.CourierQueryReplyReadLength,
		g.CourierQueryReplyWriteLength,
		g.NIKEName,
		g.SignatureSchemeName)
}

// calculateCourierQueryReadLength computes the exact size for read operations
func (g *Geometry) calculateCourierQueryReadLength() int {
	nikeScheme := g.NIKEScheme()

	// ReplicaRead: just the BoxID (using BACAP constant)
	replicaReadSize := bacap.BoxIDSize

	// ReplicaInnerMessage wrapping ReplicaRead (calculate dynamically like old geometry)
	replicaInnerMessageSize := messageTypeSize + replicaReadSize // MessageType + ReplicaRead

	// MKEM encryption of ReplicaInnerMessage
	mkemCiphertextSize := replicaInnerMessageSize + mkemEncryptionOverhead

	// CourierEnvelope containing the MKEM ciphertext
	// Use NIKE scheme to get the sender public key size (MKEM uses NIKE keys)
	senderPubkeySize := nikeScheme.PublicKeySize() // Get NIKE public key size

	// Calculate CourierEnvelope overhead dynamically like old geometry
	courierEnvelopeOverhead := calculateCourierEnvelopeOverhead(mkemCiphertextSize, senderPubkeySize)
	courierEnvelopeSize := courierEnvelopeOverhead + mkemCiphertextSize

	// Calculate CourierQuery wrapper overhead dynamically like old geometry
	courierQueryWrapperOverhead := calculateCourierQueryWrapperOverhead(courierEnvelopeSize, nikeScheme)
	return courierEnvelopeSize + courierQueryWrapperOverhead
}

// calculateCourierQueryWriteLength computes the exact size for write operations
func (g *Geometry) calculateCourierQueryWriteLength() int {
	nikeScheme := g.NIKEScheme()

	// BACAP-encrypted payload (MaxPlaintextPayloadLength + length prefix + BACAP overhead)
	bacapPayloadSize := g.MaxPlaintextPayloadLength + lengthPrefixSize + bacapEncryptionOverhead

	// ReplicaWrite containing the BACAP payload
	// BoxID + Signature + PayloadLen + BACAP payload (using actual scheme sizes)
	replicaWriteSize := replicaWriteFixedOverhead() + bacapPayloadSize

	// ReplicaInnerMessage wrapping ReplicaWrite (calculate dynamically like old geometry)
	replicaInnerMessageSize := messageTypeSize + replicaWriteSize // MessageType + ReplicaWrite

	// MKEM encryption of ReplicaInnerMessage
	mkemCiphertextSize := replicaInnerMessageSize + mkemEncryptionOverhead

	// CourierEnvelope containing the MKEM ciphertext
	// Use NIKE scheme to get the sender public key size (MKEM uses NIKE keys)
	senderPubkeySize := nikeScheme.PublicKeySize() // Get NIKE public key size

	// Calculate CourierEnvelope overhead dynamically like old geometry
	courierEnvelopeOverhead := calculateCourierEnvelopeOverhead(mkemCiphertextSize, senderPubkeySize)
	courierEnvelopeSize := courierEnvelopeOverhead + mkemCiphertextSize

	// Calculate CourierQuery wrapper overhead dynamically like old geometry
	courierQueryWrapperOverhead := calculateCourierQueryWrapperOverhead(courierEnvelopeSize, nikeScheme)
	return courierEnvelopeSize + courierQueryWrapperOverhead
}

// calculateCourierQueryReplyReadLength computes the exact size for read replies
func (g *Geometry) calculateCourierQueryReplyReadLength() int {
	// ReplicaReadReply containing the user payload
	// BoxID + Success + PayloadLen + Payload + Signature (using BACAP constants)
	replicaReadReplyFixedSize := bacap.BoxIDSize + successFieldSize + payloadLenFieldSize + bacap.SignatureSize // BoxID + Success + PayloadLen + Signature
	replicaReadReplySize := replicaReadReplyFixedSize + g.MaxPlaintextPayloadLength

	// ReplicaMessageReplyInnerMessage wrapping ReplicaReadReply (calculate dynamically)
	replicaMessageReplySize := messageTypeSize + replicaReadReplySize // MessageType + ReplicaReadReply

	// MKEM encryption of ReplicaMessageReplyInnerMessage
	mkemCiphertextSize := replicaMessageReplySize + mkemEncryptionOverhead

	// CourierEnvelopeReply containing the MKEM ciphertext (calculate dynamically)
	courierEnvelopeReplyFixedSize := successFieldSize + timestampFieldSize + ciphertextLenFieldSize // Success + Timestamp + CiphertextLen
	courierEnvelopeReplySize := courierEnvelopeReplyFixedSize + mkemCiphertextSize

	// CourierQueryReply wrapping CourierEnvelopeReply (no ErrorMsg for success, calculate dynamically)
	return errorLenFieldSize + courierEnvelopeReplySize
}

// calculateCourierQueryReplyWriteLength computes the exact size for write replies
func (g *Geometry) calculateCourierQueryReplyWriteLength() int {
	// ReplicaWriteReply with minimal response (just success confirmation)
	// WriteReplyLen + minimal WriteReply (e.g., "OK")
	replicaWriteReplySize := writeReplyLenFieldSize + minimalOkReplySize

	// ReplicaMessageReplyInnerMessage wrapping ReplicaWriteReply (calculate dynamically)
	replicaMessageReplySize := messageTypeSize + replicaWriteReplySize // MessageType + ReplicaWriteReply

	// MKEM encryption of ReplicaMessageReplyInnerMessage
	mkemCiphertextSize := replicaMessageReplySize + mkemEncryptionOverhead

	// CourierEnvelopeReply containing the MKEM ciphertext (calculate dynamically)
	courierEnvelopeReplyFixedSize := successFieldSize + timestampFieldSize + ciphertextLenFieldSize // Success + Timestamp + CiphertextLen
	courierEnvelopeReplySize := courierEnvelopeReplyFixedSize + mkemCiphertextSize

	// CourierQueryReply wrapping CourierEnvelopeReply (no ErrorMsg for success, calculate dynamically)
	return errorLenFieldSize + courierEnvelopeReplySize
}

// CalculateBoxCiphertextLength calculates the ciphertext size for a Box.
func (g *Geometry) CalculateBoxCiphertextLength() int {
	return g.MaxPlaintextPayloadLength + lengthPrefixSize + bacapEncryptionOverhead
}

// CalculateCourierEnvelopeCiphertextSizeRead calculates the MKEM ciphertext size
// for a CourierEnvelope containing a read query.
func (g *Geometry) CalculateCourierEnvelopeCiphertextSizeRead() int {
	// For read queries, the ciphertext contains a ReplicaInnerMessage with a ReplicaRead
	// ReplicaRead: just the BoxID (using BACAP constant)
	replicaReadSize := bacap.BoxIDSize

	// ReplicaInnerMessage wrapping ReplicaRead
	replicaInnerMessageSize := messageTypeSize + replicaReadSize // MessageType + ReplicaRead

	// MKEM encryption of ReplicaInnerMessage
	mkemCiphertextSize := replicaInnerMessageSize + mkemEncryptionOverhead

	return mkemCiphertextSize
}

// CalculateCourierEnvelopeCiphertextSizeWrite calculates the MKEM ciphertext size
// for a CourierEnvelope containing a write query.
func (g *Geometry) CalculateCourierEnvelopeCiphertextSizeWrite() int {
	// For write queries, the ciphertext contains a ReplicaInnerMessage with a ReplicaWrite
	// The ReplicaWrite contains the BACAP-encrypted payload
	bacapCiphertextSize := g.CalculateBoxCiphertextLength()

	// ReplicaWrite containing the BACAP payload
	// BoxID + Signature + PayloadLen + BACAP payload (using actual scheme sizes)
	replicaWriteSize := replicaWriteFixedOverhead() + bacapCiphertextSize

	// ReplicaInnerMessage wrapping ReplicaWrite
	replicaInnerMessageSize := messageTypeSize + replicaWriteSize // MessageType + ReplicaWrite

	// MKEM encryption of ReplicaInnerMessage
	mkemCiphertextSize := replicaInnerMessageSize + mkemEncryptionOverhead

	return mkemCiphertextSize
}

// CalculateEnvelopeReplySizeRead calculates the size of the EnvelopeReply
// for a read operation (ReplicaMessageReply.EnvelopeReply field).
func (g *Geometry) CalculateEnvelopeReplySizeRead() int {
	// For read replies, the EnvelopeReply contains an encrypted ReplicaMessageReplyInnerMessage
	// with a ReplicaReadReply containing the BACAP-encrypted payload

	// ReplicaReadReply structure:
	// - ErrorCode: 1 byte
	// - BoxID: 32 bytes (bacap.BoxIDSize)
	// - Signature: 64 bytes (bacap.SignatureSize)
	// - PayloadLen: 4 bytes (uint32)
	// - Payload: BACAP ciphertext (MaxPlaintextPayloadLength + lengthPrefix + bacapOverhead)
	bacapCiphertextSize := g.CalculateBoxCiphertextLength()
	replicaReadReplySize := errorCodeFieldSize + bacap.BoxIDSize + bacap.SignatureSize + payloadLenFieldSize + bacapCiphertextSize

	// ReplicaMessageReplyInnerMessage wrapping ReplicaReadReply
	// MessageType: 1 byte + ReplicaReadReply
	replicaMessageReplyInnerSize := messageTypeSize + replicaReadReplySize

	// MKEM EnvelopeReply encryption overhead (nonce + auth tag)
	// This is different from full MKEM - it's just AEAD encryption
	envelopeReplyOverhead := chacha20poly1305.NonceSize + chacha20poly1305.Overhead

	return replicaMessageReplyInnerSize + envelopeReplyOverhead
}

// CalculateEnvelopeReplySizeWrite calculates the size of the EnvelopeReply
// for a write operation (ReplicaMessageReply.EnvelopeReply field).
func (g *Geometry) CalculateEnvelopeReplySizeWrite() int {
	// For write replies, the EnvelopeReply contains an encrypted ReplicaMessageReplyInnerMessage
	// with a ReplicaWriteReply (just an error code)

	// ReplicaWriteReply structure:
	// - ErrorCode: 1 byte
	replicaWriteReplySize := errorCodeFieldSize

	// ReplicaMessageReplyInnerMessage wrapping ReplicaWriteReply
	// MessageType: 1 byte + ReplicaWriteReply
	replicaMessageReplyInnerSize := messageTypeSize + replicaWriteReplySize

	// MKEM EnvelopeReply encryption overhead (nonce + auth tag)
	// This is different from full MKEM - it's just AEAD encryption
	envelopeReplyOverhead := chacha20poly1305.NonceSize + chacha20poly1305.Overhead

	return replicaMessageReplyInnerSize + envelopeReplyOverhead
}

// MaxCourierEnvelopePlaintext calculates the maximum plaintext size that can be
// encrypted into a CourierEnvelope such that the serialized CourierEnvelope fits
// within a Box (MaxPlaintextPayloadLength).
//
// This is used for the Copy command where CourierEnvelopes are written to a
// temporary copy stream. Each CourierEnvelope must fit in a Box.
//
// The calculation works backwards from the Box size:
// Box payload = CourierEnvelope serialized size
// CourierEnvelope = CourierEnvelopeOverhead + MKEMCiphertext
// MKEMCiphertext = ReplicaInnerMessage + MKEMOverhead
// ReplicaInnerMessage = MessageType + ReplicaWrite
// ReplicaWrite = ReplicaWriteFixedOverhead + BACAPCiphertext
// BACAPCiphertext = Plaintext + LengthPrefix + BACAPOverhead
func (g *Geometry) MaxCourierEnvelopePlaintext() int {
	nikeScheme := g.NIKEScheme()
	senderPubkeySize := nikeScheme.PublicKeySize()

	// Start with the Box payload size (what we need to fit into)
	boxPayloadSize := g.MaxPlaintextPayloadLength

	// Subtract CourierEnvelope overhead (fixed fields + sender pubkey)
	// Note: We pass 0 for ciphertext size since we're calculating overhead only
	courierEnvelopeOverhead := calculateCourierEnvelopeOverhead(0, senderPubkeySize)
	boxPayloadSize -= courierEnvelopeOverhead

	// Subtract MKEM encryption overhead
	boxPayloadSize -= mkemEncryptionOverhead

	// Subtract ReplicaInnerMessage overhead (MessageType discriminator)
	boxPayloadSize -= messageTypeSize

	// Subtract ReplicaWrite fixed overhead (BoxID + Signature + PayloadLen)
	boxPayloadSize -= replicaWriteFixedOverhead()

	// Subtract BACAP encryption overhead
	boxPayloadSize -= bacapEncryptionOverhead

	// Subtract length prefix overhead
	boxPayloadSize -= lengthPrefixSize

	// What remains is the maximum plaintext size
	return boxPayloadSize
}
