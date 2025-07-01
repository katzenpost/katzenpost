// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package geo

import (
	"errors"
	"fmt"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// Geometry provides mathematically precise geometry calculations using
// trunnel's fixed binary format. No more variable overhead!
//
// It supports 3 distinct use cases:
// 1. Given BoxPayloadLength → derive all envelope sizes
// 2. Given precomputed Geometry → derive accommodating Sphinx Geometry
// 3. Given Sphinx Geometry constraint → derive optimal Geometry
type Geometry struct {
	// Core payload size
	BoxPayloadLength int

	// Calculated envelope sizes
	CourierQueryReadLength       int
	CourierQueryWriteLength      int
	CourierQueryReplyReadLength  int
	CourierQueryReplyWriteLength int

	// Crypto scheme names
	NIKEName            string
	SignatureSchemeName string
}

const (
	// BACAP encryption overhead
	bacapEncryptionOverhead = 16

	// Length prefix for padded payloads
	lengthPrefixSize = 4

	// MKEM encryption overhead (ChaCha20-Poly1305)
	mkemEncryptionOverhead = 28

	// Signature scheme (always Ed25519 for BACAP)
	signatureSchemeName = "Ed25519"

	// Message type field size
	messageTypeSize = 1

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
)

// replicaWriteFixedOverhead calculates the fixed overhead for ReplicaWrite using actual BACAP sizes
func replicaWriteFixedOverhead() int {
	return bacap.BoxIDSize + bacap.SignatureSize + payloadLenFieldSize // BoxID + Signature + PayloadLen
}

// calculateCourierEnvelopeOverhead dynamically calculates the overhead for CourierEnvelope
func calculateCourierEnvelopeOverhead(_ int, senderPubkeySize int) int {
	// CourierEnvelope fixed fields from trunnel definition
	const intermediateReplicasSize = 2 // [2]uint8
	const dek1Size = 60                // [60]uint8
	const dek2Size = 60                // [60]uint8
	const replyIndexSize = 1           // uint8
	const epochSize = 8                // uint64
	const senderPubkeyLenSize = 2      // uint16
	const ciphertextLenSize = 4        // uint32

	courierEnvelopeFixedOverhead := intermediateReplicasSize + dek1Size + dek2Size +
		replyIndexSize + epochSize + senderPubkeyLenSize + ciphertextLenSize

	return courierEnvelopeFixedOverhead + senderPubkeySize
}

// calculateCourierQueryWrapperOverhead dynamically calculates the overhead for CourierQuery wrapper
func calculateCourierQueryWrapperOverhead(_ int, _ nike.Scheme) int {
	// CourierQuery union fields from trunnel serialization:
	// QueryType: uint8 = 1 byte (union discriminator)
	// Envelope: *CourierEnvelope (embedded struct, no length prefix)
	// CopyCommand: *CopyCommand (mutually exclusive with Envelope)
	const queryTypeSize = 1 // uint8 discriminator

	return queryTypeSize
}

// NewGeometry creates a Geometry from BoxPayloadLength (Use Case 1)
//
// This is the most common use case: given a desired payload size, calculate
// all the envelope sizes with mathematical precision using trunnel's fixed format.
func NewGeometry(boxPayloadLength int, nikeScheme nike.Scheme) *Geometry {
	g := &Geometry{
		BoxPayloadLength:    boxPayloadLength,
		NIKEName:            nikeScheme.Name(),
		SignatureSchemeName: signatureSchemeName,
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
// BoxPayloadLength that maximizes usage of the available space by directly calculating
// the overhead layers and subtracting them from the target size.
func NewGeometryFromSphinx(sphinxGeo *geo.Geometry, nikeScheme nike.Scheme) (*Geometry, error) {
	targetSize := sphinxGeo.UserForwardPayloadLength

	// Calculate all overhead layers for CourierQueryWrite (the largest envelope type)
	// Working backwards from CourierQuery to BoxPayloadLength:

	// 1. CourierQuery wrapper overhead
	courierQueryOverhead := 1 // QueryType discriminator

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

	// Calculate total overhead
	totalOverhead := courierQueryOverhead + courierEnvelopeOverhead + mkemOverhead +
		replicaInnerMessageOverhead + replicaWriteOverhead + bacapOverhead

	// Calculate the BoxPayloadLength by subtracting all overheads from target
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
	if g.BoxPayloadLength <= 0 {
		return errors.New("BoxPayloadLength must be positive")
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
	return g.BoxPayloadLength + lengthPrefixSize
}

// String returns a human-readable representation
func (g *Geometry) String() string {
	return fmt.Sprintf(`Geometry:
  BoxPayloadLength: %d bytes
  CourierQueryReadLength: %d bytes  
  CourierQueryWriteLength: %d bytes
  CourierQueryReplyReadLength: %d bytes
  CourierQueryReplyWriteLength: %d bytes
  NIKEName: %s
  SignatureSchemeName: %s`,
		g.BoxPayloadLength,
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

	// BACAP-encrypted payload (padded payload already includes length prefix + BACAP overhead)
	bacapPayloadSize := g.BoxPayloadLength + bacapEncryptionOverhead

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
	replicaReadReplySize := replicaReadReplyFixedSize + g.BoxPayloadLength

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
