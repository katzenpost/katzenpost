// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

const (
	SignatureSchemeName = "Ed25519"
)

// Helper function for max
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var (
	// Create reusable EncMode interface with immutable options, safe for concurrent use.
	ccbor cbor.EncMode
)

// Geometry describes the geometry of the Pigeonhole Protocol messages.
// It has 3 distinct use cases:
// 1. specify BoxPayloadLength and derive appropriate PigeonholeGeometry and SphinxGeometry objects.
// 2. specify a precomputed PigeonholeGeometry and derive accommodating SphinxGeometry object.
// 3. specify a precomputed SphinxGeometry as a size constraint and derive a PigeonholeGeometry object.
type Geometry struct {

	// CourierEnvelopeLength is the length of the CBOR serialized CourierEnvelope message.
	CourierEnvelopeLength int

	// CourierEnvelopeReplyLength is the length of the CBOR serialized CourierEnvelopeReply message.
	CourierEnvelopeReplyLength int

	// NikeName is the name of the NIKE scheme used by our MKEM scheme to encrypt
	// the CourierEnvelope and CourierEnvelopeReply messages.
	NIKEName string

	// SignatureSchemeName is the name of the signature scheme used
	// by BACAP to sign payloads.
	SignatureSchemeName string

	// BoxPayloadLength is the size of the usable payload that is end to end encrypted at rest
	// by means of the BACAP protocol described in section 4 of our paper, EchoMix.
	BoxPayloadLength int
}

// NewGeometry solves Use Case 1: specify BoxPayloadLength and derive appropriate
// Pigeonhole Geometry object using default schemes.
//
// This constructor takes a desired BoxPayloadLength (the usable payload size for
// BACAP-encrypted messages) and creates a PigeonholeGeometry with calculated envelope
// lengths using the default NIKE scheme (CTIDH1024-X25519) and signature scheme (Ed25519).
//
// This is a convenience constructor for the most common use case. For more control over
// the NIKE scheme, use GeometryFromBoxPayloadLength() instead.
//
// Parameters:
//   - boxPayloadLength: The desired size of the usable payload in bytes
//
// Returns:
//   - *Geometry: The pigeonhole geometry with calculated envelope lengths
func NewGeometry(boxPayloadLength int) *Geometry {
	g := &Geometry{
		BoxPayloadLength:           boxPayloadLength,
		SignatureSchemeName:        SignatureSchemeName,
		NIKEName:                   NikeScheme.Name(),
		CourierEnvelopeLength:      courierEnvelopeLength(boxPayloadLength, NikeScheme),
		CourierEnvelopeReplyLength: courierEnvelopeReplyLength(),
	}
	return g
}

func (g *Geometry) courierEnvelopeOverhead() int {
	const (
		intermediateReplicasLength = 2  // [2]uint8
		epochLength                = 8  // uint64
		isReadLength               = 1  // bool
		replyIndexLength           = 1  // uint8
		chachaPolyNonceLength      = 12 // ChaCha20Poly1305 nonce
		chachaPolyTagLength        = 16 // Poly1305 authentication tag
		cborOverhead               = 53 // CBOR serialization overhead
	)
	return intermediateReplicasLength + (2 * mkem.DEKSize) +
		replyIndexLength + epochLength +
		g.NIKEScheme().PublicKeySize() + isReadLength +
		chachaPolyNonceLength + chachaPolyTagLength + cborOverhead
}

func (g *Geometry) courierEnvelopeReplyOverhead() int {
	const (
		envelopeHashLength    = hash.HashSize // 32 bytes - *[hash.HashSize]byte
		replyIndexLength      = 1             // 1 byte - uint8
		errorCodeLength       = 1             // 1 byte - uint8
		chachaPolyNonceLength = 12            // ChaCha20Poly1305 nonce
		chachaPolyTagLength   = 16            // Poly1305 authentication tag
		cborOverhead          = 20            // CBOR serialization overhead
	)

	return envelopeHashLength + replyIndexLength + errorCodeLength +
		chachaPolyNonceLength + chachaPolyTagLength + cborOverhead
}

// replicaInnerMessageOverhead calculates the overhead for ReplicaInnerMessage.
// ReplicaInnerMessage is a CBOR map with 2 fields where exactly one is non-nil.
// We use the actual overhead calculations for each case and add CBOR union overhead.
func (g *Geometry) replicaInnerMessageOverhead() int {
	const (
		// CBOR overhead for ReplicaInnerMessage struct with 2 pointer fields
		cborMapHeader      = 1  // CBOR map type indicator
		replicaReadKeyLen  = 12 // "ReplicaRead" field name length
		replicaWriteKeyLen = 13 // "ReplicaWrite" field name length
		nilValueOverhead   = 1  // CBOR nil value for unused field
		cborFieldOverhead  = 2  // CBOR field encoding overhead per field

		// Additional CBOR overhead when embedding ReplicaWrite in ReplicaInnerMessage
		// This accounts for the extra CBOR serialization overhead of the nested structure
		replicaWriteEmbeddingOverhead = 28

		// Total CBOR struct overhead for the union type
		unionStructOverhead = cborMapHeader + replicaReadKeyLen + replicaWriteKeyLen +
			nilValueOverhead + (2 * cborFieldOverhead)
	)

	// ReplicaRead case: union overhead + actual ReplicaRead overhead
	replicaReadCaseOverhead := unionStructOverhead + g.replicaReadOverhead()

	// ReplicaWrite case: union overhead + actual ReplicaWrite overhead + embedding overhead
	replicaWriteCaseOverhead := unionStructOverhead + g.replicaWriteOverhead() + replicaWriteEmbeddingOverhead

	// Return the maximum to accommodate either case
	if replicaReadCaseOverhead > replicaWriteCaseOverhead {
		return replicaReadCaseOverhead
	}
	return replicaWriteCaseOverhead
}

func (g *Geometry) replicaReadLength() int {
	return g.SignatureScheme().PublicKeySize()
}

// replicaReadOverhead calculates the overhead of the ReplicaRead message.
// ReplicaRead only contains a BoxID (Ed25519 public key) and is CBOR serialized.
func (g *Geometry) replicaReadOverhead() int {
	boxIDLength := g.SignatureScheme().PublicKeySize()
	// CBOR overhead for a simple struct with one field
	cborOverhead := 9 // CBOR overhead for struct with one 32-byte field
	return boxIDLength + cborOverhead
}

// note that here we calculate the overhead of the ReplicaWrite message without padding
// because we only care about these message types in the context of being transported
// over the mixnet in a Sphinx packet payload.
func (g *Geometry) replicaWriteOverhead() int {
	const (
		// BACAP uses AES-GCM-SIV which adds 16 bytes of authentication tag overhead
		bacapEncryptionOverhead = 16
	)

	boxIDLength := g.SignatureScheme().PublicKeySize()
	signatureLength := g.SignatureScheme().SignatureSize()
	return commands.CmdOverhead + boxIDLength + signatureLength + bacapEncryptionOverhead
}

// Validate returns an error if one of it's validation checks fails.
func (g *Geometry) Validate() error {
	if g == nil {
		return errors.New("geometry reference is nil")
	}
	if g.NIKEName != "" {
		mynike := schemes.ByName(g.NIKEName)
		if mynike == nil {
			return fmt.Errorf("geometry has invalid NIKE Scheme %s", g.NIKEName)
		}
	} else {
		return errors.New("geometry NIKEName is not set")
	}
	if g.SignatureSchemeName != SignatureSchemeName {
		return errors.New("geometry SignatureSchemeName must be set to Ed25519")
	}
	if g.BoxPayloadLength == 0 {
		return errors.New("geometry UserForwardPayloadLength is not set")
	}
	return nil
}

func (g *Geometry) NIKEScheme() nike.Scheme {
	s := schemes.ByName(g.NIKEName)
	if s == nil {
		panic("failed to get a scheme")
	}
	return s
}

func (g *Geometry) SignatureScheme() sign.Scheme {
	s := signSchemes.ByName(g.SignatureSchemeName)
	if s == nil {
		panic("failed to get a scheme")
	}
	return s
}

func (g *Geometry) String() string {
	var b strings.Builder
	b.WriteString("pigeonhole_geometry:\n")
	b.WriteString(fmt.Sprintf("CourierEnvelopeLength: %d\n", g.CourierEnvelopeLength))
	b.WriteString(fmt.Sprintf("CourierEnvelopeReplyLength: %d\n", g.CourierEnvelopeReplyLength))
	b.WriteString(fmt.Sprintf("NIKEName: %s\n", g.NIKEName))
	b.WriteString(fmt.Sprintf("SignatureSchemeName: %s\n", g.SignatureSchemeName))
	b.WriteString(fmt.Sprintf("UserForwardPayloadLength: %d\n", g.BoxPayloadLength))
	return b.String()
}

type Config struct {
	PigeonholeGeometry *Geometry
}

func (g *Geometry) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	encoder := toml.NewEncoder(buf)
	config := &Config{
		PigeonholeGeometry: g,
	}
	err := encoder.Encode(config)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (g *Geometry) Display() string {
	blob, err := g.Marshal()
	if err != nil {
		panic(err)
	}
	return string(blob)
}

func (g *Geometry) bytes() []byte {
	blob, err := ccbor.Marshal(g)
	if err != nil {
		panic(err)
	}
	return blob
}

func (g *Geometry) Hash() []byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, err = h.Write(g.bytes())
	if err != nil {
		panic(err)
	}
	return h.Sum(nil)
}

func courierEnvelopeLength(boxPayloadLength int, nikeScheme nike.Scheme) int {
	// Create a temporary geometry to use existing methods
	tempGeo := &Geometry{
		BoxPayloadLength:    boxPayloadLength,
		NIKEName:            nikeScheme.Name(),
		SignatureSchemeName: SignatureSchemeName,
	}

	// CourierEnvelope contains MKEM-encrypted ReplicaInnerMessage
	// ReplicaInnerMessage contains either ReplicaRead or ReplicaWrite
	// We need to calculate the larger of the two cases

	// Case 1: ReplicaRead - just contains a BoxID
	replicaReadSize := tempGeo.replicaReadOverhead()
	replicaInnerMessageReadSize := replicaInnerMessageOverheadForRead() + replicaReadSize

	// Case 2: ReplicaWrite - contains BoxID + Signature + BACAP-encrypted payload
	replicaWriteSize := tempGeo.replicaWriteOverhead() + boxPayloadLength
	replicaInnerMessageWriteSize := replicaInnerMessageOverheadForWrite() + replicaWriteSize

	// Take the maximum of the two cases
	maxReplicaInnerMessageSize := max(replicaInnerMessageReadSize, replicaInnerMessageWriteSize)

	// Add MKEM encryption overhead and CourierEnvelope overhead
	return tempGeo.courierEnvelopeOverhead() + mkemEncryptionOverhead(maxReplicaInnerMessageSize, nikeScheme)
}

func mkemEncryptionOverhead(plaintextSize int, nikeScheme nike.Scheme) int {
	const (
		chachaPolyNonceLength = 12 // ChaCha20Poly1305 nonce
		chachaPolyTagLength   = 16 // Poly1305 authentication tag
	)

	// MKEM encryption overhead includes:
	// - Ephemeral public key size
	// - ChaCha20Poly1305 nonce and tag
	// - The actual ciphertext is the same size as plaintext
	return nikeScheme.PublicKeySize() + chachaPolyNonceLength + chachaPolyTagLength + plaintextSize
}

func courierEnvelopeReplyLength() int {
	const (
		envelopeHashLength    = hash.HashSize // 32 bytes - *[hash.HashSize]byte
		replyIndexLength      = 1             // 1 byte - uint8
		errorCodeLength       = 1             // 1 byte - uint8
		chachaPolyNonceLength = 12            // ChaCha20Poly1305 nonce
		chachaPolyTagLength   = 16            // Poly1305 authentication tag
		cborOverhead          = 20            // CBOR serialization overhead
	)

	return envelopeHashLength + replyIndexLength + errorCodeLength +
		chachaPolyNonceLength + chachaPolyTagLength + cborOverhead
}

func replicaInnerMessageOverheadForRead() int {
	const (
		// CBOR overhead for ReplicaInnerMessage struct with 2 pointer fields
		cborMapHeader      = 1  // CBOR map type indicator
		replicaReadKeyLen  = 12 // "ReplicaRead" field name length
		replicaWriteKeyLen = 13 // "ReplicaWrite" field name length
		nilValueOverhead   = 1  // CBOR nil value for unused field
		cborFieldOverhead  = 2  // CBOR field encoding overhead per field

		// Total CBOR struct overhead for the union type
		unionStructOverhead = cborMapHeader + replicaReadKeyLen + replicaWriteKeyLen +
			nilValueOverhead + (2 * cborFieldOverhead)
	)
	return unionStructOverhead
}

func replicaInnerMessageOverheadForWrite() int {
	const (
		// CBOR overhead for ReplicaInnerMessage struct with 2 pointer fields
		cborMapHeader      = 1  // CBOR map type indicator
		replicaReadKeyLen  = 12 // "ReplicaRead" field name length
		replicaWriteKeyLen = 13 // "ReplicaWrite" field name length
		nilValueOverhead   = 1  // CBOR nil value for unused field
		cborFieldOverhead  = 2  // CBOR field encoding overhead per field

		// Additional CBOR overhead when embedding ReplicaWrite in ReplicaInnerMessage
		// This accounts for the extra CBOR serialization overhead of the nested structure
		replicaWriteEmbeddingOverhead = 28

		// Total CBOR struct overhead for the union type
		unionStructOverhead = cborMapHeader + replicaReadKeyLen + replicaWriteKeyLen +
			nilValueOverhead + (2 * cborFieldOverhead)
	)
	return unionStructOverhead + replicaWriteEmbeddingOverhead
}

func findMaxBoxPayloadLength(maxCourierEnvelopeLength int, nikeScheme nike.Scheme) int {
	// Binary search to find the maximum BoxPayloadLength that fits within the constraint
	low := 0
	high := maxCourierEnvelopeLength // Upper bound estimate

	for low <= high {
		mid := (low + high) / 2

		if courierEnvelopeLength(mid, nikeScheme) <= maxCourierEnvelopeLength {
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	return high // Return the largest value that fits
}

// GeometryFromBoxPayloadLength solves Use Case 1: specify BoxPayloadLength and derive
// appropriate PigeonholeGeometry object.
//
// This function takes a desired BoxPayloadLength (the usable payload size for BACAP-encrypted
// messages) and creates a PigeonholeGeometry with calculated envelope lengths that can
// accommodate that payload size.
//
// Parameters:
//   - boxPayloadLength: The desired size of the usable payload in bytes
//   - nikeScheme: The NIKE scheme to use for MKEM encryption
//
// Returns:
//   - *Geometry: The pigeonhole geometry with calculated envelope lengths
func GeometryFromBoxPayloadLength(boxPayloadLength int, nikeScheme nike.Scheme) *Geometry {
	return &Geometry{
		CourierEnvelopeLength:      courierEnvelopeLength(boxPayloadLength, nikeScheme),
		CourierEnvelopeReplyLength: courierEnvelopeReplyLength(),
		NIKEName:                   nikeScheme.Name(),
		SignatureSchemeName:        SignatureSchemeName,
		BoxPayloadLength:           boxPayloadLength,
	}
}

// GeometryFromPigeonholeGeometry solves Use Case 2: specify a precomputed PigeonholeGeometry
// and derive accommodating SphinxGeometry object.
//
// This function takes an existing PigeonholeGeometry (perhaps loaded from configuration)
// and creates a SphinxGeometry that can accommodate the pigeonhole messages. This is useful
// when the pigeonhole parameters are fixed and you need to determine the required Sphinx
// packet size.
//
// Parameters:
//   - pigeonholeGeometry: An existing pigeonhole geometry with known envelope lengths
//   - nrHops: The number of hops for the Sphinx packet
//
// Returns:
//   - *geo.Geometry: The sphinx geometry sized to accommodate the pigeonhole messages
func GeometryFromPigeonholeGeometry(pigeonholeGeometry *Geometry, nrHops int) *geo.Geometry {
	nikeScheme := schemes.ByName(pigeonholeGeometry.NIKEName)
	if nikeScheme == nil {
		panic(fmt.Sprintf("invalid NIKE scheme: %s", pigeonholeGeometry.NIKEName))
	}

	// The Sphinx geometry needs to accommodate the CourierEnvelope
	// (CourierEnvelopeReply is smaller, so CourierEnvelope is the constraint)
	maxPigeonholeMessageSize := pigeonholeGeometry.CourierEnvelopeLength
	return geo.GeometryFromUserForwardPayloadLength(nikeScheme, maxPigeonholeMessageSize, true, nrHops)
}

// GeometryFromSphinxGeometry solves Use Case 3: specify a precomputed SphinxGeometry as a
// size constraint and derive a PigeonholeGeometry object.
//
// This function takes an existing SphinxGeometry (perhaps constrained by network requirements)
// and determines the maximum BoxPayloadLength that can fit within the Sphinx packet size
// constraints. It then creates a PigeonholeGeometry that maximizes payload utilization
// while staying within the Sphinx limits.
//
// Parameters:
//   - sphinxGeometry: An existing sphinx geometry that constrains the maximum message size
//
// Returns:
//   - *Geometry: The pigeonhole geometry with maximum BoxPayloadLength that fits the constraint
func GeometryFromSphinxGeometry(sphinxGeometry *geo.Geometry) *Geometry {
	// Use the default Pigeonhole NIKE scheme, NOT the Sphinx NIKE scheme
	// These are independent cryptographic layers
	pigeonholeNikeScheme := NikeScheme

	// Calculate the maximum BoxPayloadLength that fits within the Sphinx constraint
	// The constraint is the UserForwardPayloadLength from Sphinx
	maxPayloadSize := sphinxGeometry.UserForwardPayloadLength

	// Use binary search to find the maximum BoxPayloadLength that fits
	boxPayloadLength := findMaxBoxPayloadLength(maxPayloadSize, pigeonholeNikeScheme)
	if boxPayloadLength <= 0 {
		// Calculate minimum required size for debugging
		minRequired := courierEnvelopeLength(1, pigeonholeNikeScheme)
		panic(fmt.Sprintf("Sphinx geometry too small: UserForwardPayloadLength=%d, need at least %d",
			maxPayloadSize, minRequired))
	}

	return &Geometry{
		CourierEnvelopeLength:      courierEnvelopeLength(boxPayloadLength, pigeonholeNikeScheme),
		CourierEnvelopeReplyLength: courierEnvelopeReplyLength(),
		NIKEName:                   pigeonholeNikeScheme.Name(),
		SignatureSchemeName:        SignatureSchemeName,
		BoxPayloadLength:           boxPayloadLength,
	}
}

func init() {
	var err error
	opts := cbor.CanonicalEncOptions()
	ccbor, err = opts.EncMode()
	if err != nil {
		panic(err)
	}
}
