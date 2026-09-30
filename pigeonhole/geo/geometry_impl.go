// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !thinclient

package geo

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/katzenpost/chacha20poly1305"
	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/mrhybrid"
	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// replicaWriteFixedOverhead calculates the fixed overhead for ReplicaWrite using actual BACAP sizes
func replicaWriteFixedOverhead() int {
	return bacap.BoxIDSize + bacap.SignatureSize + payloadLenFieldSize // BoxID + Signature + PayloadLen
}

// calculateCourierEnvelopeOverhead dynamically calculates the overhead for
// CourierEnvelope. kemCiphertextSize is the wire size of ONE intermediate
// replica's KEM ciphertext; mrhybrid has no shared ephemeral key, so both
// of the 2 intermediate replicas carry their own ciphertext and length prefix.
func calculateCourierEnvelopeOverhead(_ int, kemCiphertextSize int) int {
	// CourierEnvelope fixed fields from trunnel definition
	courierEnvelopeFixedOverhead := intermediateReplicasSize + mrhybrid.DEKSize + mrhybrid.DEKSize +
		replyIndexSize + epochSize + 2*kemCiphertextLenSize + ciphertextLenFieldSize

	return courierEnvelopeFixedOverhead + 2*kemCiphertextSize
}

// calculateCourierQueryWrapperOverhead dynamically calculates the overhead for CourierQuery wrapper
func calculateCourierQueryWrapperOverhead(_ int, _ kem.Scheme) int {
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
func NewGeometry(boxPayloadLength int, kemScheme kem.Scheme) *Geometry {
	g := &Geometry{
		MaxPlaintextPayloadLength: boxPayloadLength,
		KEMName:                   kemScheme.Name(),
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
func NewGeometryFromSphinx(sphinxGeo *geo.Geometry, kemScheme kem.Scheme) (*Geometry, error) {
	targetSize := sphinxGeo.UserForwardPayloadLength

	// Calculate all overhead layers for CourierQueryWrite (the largest envelope type)
	// Working backwards from CourierQuery to MaxPlaintextPayloadLength:

	// 1. CourierQuery wrapper overhead
	courierQueryOverhead := queryTypeSize // QueryType discriminator

	// 2. CourierEnvelope overhead (fixed fields + per-recipient KEM ciphertexts)
	kemCiphertextSize := kemScheme.CiphertextSize()
	courierEnvelopeOverhead := calculateCourierEnvelopeOverhead(0, kemCiphertextSize) // Pass 0 for ciphertext size since we're calculating overhead

	// 3. Envelope AEAD overhead
	envelopeOverhead := envelopeAEADOverhead

	// 4. ReplicaInnerMessage overhead
	replicaInnerMessageOverhead := messageTypeSize

	// 5. ReplicaWrite fixed overhead
	replicaWriteOverhead := replicaWriteFixedOverhead()

	// 6. BACAP encryption overhead
	bacapOverhead := bacapEncryptionOverhead

	// 7. Length prefix overhead for the BACAP-encrypted application payload.
	lengthPrefixOverhead := lengthPrefixSize

	// 8. Length prefix overhead for the length-prefix-padded
	// ReplicaInnerMessage that sits between the trunnel encoding and the
	// envelope plaintext. This is distinct from the BACAP-layer prefix in (7)
	// and must be accounted for separately; see ReplicaInnerMessagePaddedSize.
	trunnelLengthPrefixOverhead := lengthPrefixSize

	// Calculate total overhead
	totalOverhead := courierQueryOverhead + courierEnvelopeOverhead + envelopeOverhead +
		replicaInnerMessageOverhead + replicaWriteOverhead + bacapOverhead +
		lengthPrefixOverhead + trunnelLengthPrefixOverhead

	// Calculate the MaxPlaintextPayloadLength by subtracting all overheads from target
	boxPayloadLength := targetSize - totalOverhead

	if boxPayloadLength <= 0 {
		return nil, fmt.Errorf("sphinx geometry too small: UserForwardPayloadLength=%d, total overhead=%d",
			targetSize, totalOverhead)
	}

	return NewGeometry(boxPayloadLength, kemScheme), nil
}

// ToSphinxGeometry creates an accommodating Sphinx Geometry (Use Case 2)
//
// Given a precomputed Geometry, derive a Sphinx geometry that can
// accommodate the largest envelope size.
func (g *Geometry) ToSphinxGeometry(nrHops int, withSURB bool) *geo.Geometry {
	kemScheme := g.KEMScheme()

	// Find the maximum envelope size we need to accommodate
	maxEnvelopeSize := maxInt(
		g.CourierQueryReadLength,
		g.CourierQueryWriteLength,
		g.CourierQueryReplyReadLength,
		g.CourierQueryReplyWriteLength,
	)

	// Create Sphinx geometry that can handle our largest envelope
	return geo.KEMGeometryFromUserForwardPayloadLength(kemScheme, maxEnvelopeSize, withSURB, nrHops)
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

// KEMScheme returns the KEM scheme used by this geometry
func (g *Geometry) KEMScheme() kem.Scheme {
	scheme := schemes.ByName(g.KEMName)
	if scheme == nil {
		panic(fmt.Sprintf("unknown KEM scheme: %s", g.KEMName))
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
	if g.KEMName == "" {
		return errors.New("KEMName must be set")
	}
	if g.KEMScheme() == nil {
		return fmt.Errorf("invalid KEM scheme: %s", g.KEMName)
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

// Config wraps a Geometry so that Marshal emits a `[PigeonholeGeometry]`
// TOML table, matching the shape expected in thinclient.toml. It mirrors
// the equivalent wrapper in core/sphinx/geo.
type Config struct {
	PigeonholeGeometry *Geometry
}

// Marshal serialises the geometry as a `[PigeonholeGeometry]` TOML
// table suitable for pasting verbatim into a thinclient.toml.
func (g *Geometry) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	encoder := toml.NewEncoder(buf)
	if err := encoder.Encode(&Config{PigeonholeGeometry: g}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Display returns the TOML representation produced by Marshal, panicking
// only on the impossible event of an encoding failure. It is the
// counterpart of core/sphinx/geo.Geometry.Display.
func (g *Geometry) Display() string {
	blob, err := g.Marshal()
	if err != nil {
		panic(err)
	}
	return string(blob)
}

// String returns a human-readable representation
func (g *Geometry) String() string {
	return fmt.Sprintf(`Geometry:
  MaxPlaintextPayloadLength: %d bytes
  CourierQueryReadLength: %d bytes
  CourierQueryWriteLength: %d bytes
  CourierQueryReplyReadLength: %d bytes
  CourierQueryReplyWriteLength: %d bytes
  KEMName: %s
  SignatureSchemeName: %s`,
		g.MaxPlaintextPayloadLength,
		g.CourierQueryReadLength,
		g.CourierQueryWriteLength,
		g.CourierQueryReplyReadLength,
		g.CourierQueryReplyWriteLength,
		g.KEMName,
		g.SignatureSchemeName)
}

// calculateCourierQueryReadLength computes the exact size for read operations.
// Reads are padded to the write size before encryption, so the wire-level
// CourierQuery size is the same as for writes; both go through
// calculateCourierQueryLength.
func (g *Geometry) calculateCourierQueryReadLength() int {
	return g.calculateCourierQueryLength()
}

// calculateCourierQueryWriteLength computes the exact size for write operations.
// Writes drive the padded inner-message size, so the wire-level CourierQuery
// size is the same as for reads; both go through calculateCourierQueryLength.
func (g *Geometry) calculateCourierQueryWriteLength() int {
	return g.calculateCourierQueryLength()
}

// calculateCourierQueryLength computes the wire-level CourierQuery size for
// any read or write query, accounting for the length-prefix-and-pad applied
// to the ReplicaInnerMessage before envelope encryption.
func (g *Geometry) calculateCourierQueryLength() int {
	kemScheme := g.KEMScheme()

	// The envelope plaintext is a length-prefix-padded ReplicaInnerMessage of
	// write size. Reads are padded to the same size so the read/write
	// distinction does not leak through the ciphertext length.
	envelopeCiphertextSize := g.ReplicaInnerMessagePaddedSize() + envelopeAEADOverhead

	// CourierEnvelope containing the envelope ciphertext and both
	// intermediate replicas' KEM ciphertexts.
	kemCiphertextSize := kemScheme.CiphertextSize()
	courierEnvelopeOverhead := calculateCourierEnvelopeOverhead(envelopeCiphertextSize, kemCiphertextSize)
	courierEnvelopeSize := courierEnvelopeOverhead + envelopeCiphertextSize

	// CourierQuery wrapper.
	courierQueryWrapperOverhead := calculateCourierQueryWrapperOverhead(courierEnvelopeSize, kemScheme)
	return courierEnvelopeSize + courierQueryWrapperOverhead
}

// calculateCourierQueryReplyReadLength computes the exact size for read
// replies. Write replies are padded to the read-reply size before AEAD, so
// the wire-level CourierQueryReply is the same for both variants.
func (g *Geometry) calculateCourierQueryReplyReadLength() int {
	return g.calculateCourierQueryReplyLength()
}

// calculateCourierQueryReplyWriteLength computes the exact size for write
// replies. Read replies set the padded reply-inner size, so the wire-level
// CourierQueryReply is the same for both variants.
func (g *Geometry) calculateCourierQueryReplyWriteLength() int {
	return g.calculateCourierQueryReplyLength()
}

// calculateCourierQueryReplyLength computes the wire-level CourierQueryReply
// size for any read or write reply, accounting for the length-prefix-and-pad
// applied to the ReplicaMessageReplyInnerMessage before AEAD encryption.
func (g *Geometry) calculateCourierQueryReplyLength() int {
	// AEAD plaintext is a length-prefix-padded ReplicaMessageReplyInnerMessage
	// of read-reply size. Write replies are padded to the same size so the
	// reply variant does not leak through the ciphertext length.
	envelopeCiphertextSize := g.ReplicaReplyInnerMessagePaddedSize() + envelopeAEADOverhead

	// CourierEnvelopeReply containing the AEAD ciphertext.
	courierEnvelopeReplyFixedSize := successFieldSize + timestampFieldSize + ciphertextLenFieldSize
	courierEnvelopeReplySize := courierEnvelopeReplyFixedSize + envelopeCiphertextSize

	// CourierQueryReply wrapper (no ErrorMsg for success).
	return errorLenFieldSize + courierEnvelopeReplySize
}

// ReplicaInnerMessageWriteSize returns the serialized size of a ReplicaInnerMessage
// containing a full write (the largest inbound inner message type).
// This is the bare trunnel encoding size; the padded envelope plaintext is
// reported by ReplicaInnerMessagePaddedSize.
func (g *Geometry) ReplicaInnerMessageWriteSize() int {
	bacapCiphertextSize := g.CalculateBoxCiphertextLength()
	replicaWriteSize := replicaWriteFixedOverhead() + bacapCiphertextSize
	return messageTypeSize + replicaWriteSize
}

// ReplicaInnerMessagePaddedSize returns the size of the envelope plaintext for
// any inbound ReplicaInnerMessage. Reads and writes are length-prefixed and
// padded to the write size so that the read/write distinction does not leak
// through the ciphertext length.
func (g *Geometry) ReplicaInnerMessagePaddedSize() int {
	return g.ReplicaInnerMessageWriteSize() + lengthPrefixSize
}

// ReplicaReplyInnerMessageReadSize returns the serialized size of a
// ReplicaMessageReplyInnerMessage containing a full read reply (the largest reply type).
// This is the bare trunnel encoding size; the padded plaintext is reported
// by ReplicaReplyInnerMessagePaddedSize.
func (g *Geometry) ReplicaReplyInnerMessageReadSize() int {
	bacapCiphertextSize := g.CalculateBoxCiphertextLength()
	replicaReadReplySize := errorCodeFieldSize + bacap.BoxIDSize + bacap.SignatureSize + payloadLenFieldSize + bacapCiphertextSize
	return messageTypeSize + replicaReadReplySize
}

// ReplicaReplyInnerMessagePaddedSize returns the size of the AEAD plaintext
// for any reply ReplicaMessageReplyInnerMessage. Read replies and write
// replies are length-prefixed and padded to the read-reply size so that the
// reply variant does not leak through the ciphertext length.
func (g *Geometry) ReplicaReplyInnerMessagePaddedSize() int {
	return g.ReplicaReplyInnerMessageReadSize() + lengthPrefixSize
}

// CalculateBoxCiphertextLength calculates the ciphertext size for a Box.
func (g *Geometry) CalculateBoxCiphertextLength() int {
	return g.MaxPlaintextPayloadLength + lengthPrefixSize + bacapEncryptionOverhead
}

// CalculateCourierEnvelopeCiphertextSizeRead calculates the envelope
// ciphertext size for a CourierEnvelope containing a read query. Because
// reads are padded to the write size before encryption, this is identical to
// CalculateCourierEnvelopeCiphertextSizeWrite.
func (g *Geometry) CalculateCourierEnvelopeCiphertextSizeRead() int {
	return g.ReplicaInnerMessagePaddedSize() + envelopeAEADOverhead
}

// CalculateCourierEnvelopeCiphertextSizeWrite calculates the envelope
// ciphertext size for a CourierEnvelope containing a write query. The
// envelope plaintext is a length-prefix-padded ReplicaInnerMessage of
// write-size length.
func (g *Geometry) CalculateCourierEnvelopeCiphertextSizeWrite() int {
	return g.ReplicaInnerMessagePaddedSize() + envelopeAEADOverhead
}

// CalculateEnvelopeReplySizeRead calculates the size of the EnvelopeReply
// (the AEAD ciphertext on the wire) for a read operation. The AEAD plaintext
// is a length-prefix-padded ReplicaMessageReplyInnerMessage of read-reply
// size length; write replies are padded to the same size for
// indistinguishability, so this value applies to both reply variants.
func (g *Geometry) CalculateEnvelopeReplySizeRead() int {
	envelopeReplyOverhead := chacha20poly1305.NonceSize + chacha20poly1305.Overhead
	return g.ReplicaReplyInnerMessagePaddedSize() + envelopeReplyOverhead
}

// CalculateEnvelopeReplySizeWrite is identical to CalculateEnvelopeReplySizeRead
// because write replies are padded to the read-reply size before AEAD
// encryption.
func (g *Geometry) CalculateEnvelopeReplySizeWrite() int {
	return g.CalculateEnvelopeReplySizeRead()
}
