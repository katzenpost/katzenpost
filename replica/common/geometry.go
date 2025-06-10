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
// PigeonholeGeometry object.
//
// This constructor takes a desired BoxPayloadLength (the usable payload size for
// BACAP-encrypted messages) and creates a PigeonholeGeometry with calculated envelope
// lengths. The signature scheme is always Ed25519 due to BACAP's dependency.
//
// Parameters:
//   - boxPayloadLength: The desired size of the usable payload in bytes
//   - nikeScheme: The NIKE scheme to use for MKEM encryption
//
// Returns:
//   - *Geometry: The pigeonhole geometry with calculated envelope lengths
func NewGeometry(boxPayloadLength int, nikeScheme nike.Scheme) *Geometry {
	g := &Geometry{
		BoxPayloadLength:           boxPayloadLength,
		SignatureSchemeName:        SignatureSchemeName,
		NIKEName:                   nikeScheme.Name(),
		CourierEnvelopeLength:      courierEnvelopeLength(boxPayloadLength, nikeScheme),
		CourierEnvelopeReplyLength: courierEnvelopeReplyLength(boxPayloadLength),
	}
	return g
}

func (g *Geometry) courierEnvelopeOverhead() int {
	const (
		intermediateReplicasLength = 2
		epochLength                = 8
		isReadLength               = 1
		replyIndexLength           = 1
		chachaPolyNonceLength      = 12
		chachaPolyTagLength        = 16
		cborOverhead               = 53
	)
	return intermediateReplicasLength + (2 * mkem.DEKSize) +
		replyIndexLength + epochLength +
		g.NIKEScheme().PublicKeySize() + isReadLength +
		chachaPolyNonceLength + chachaPolyTagLength + cborOverhead
}

func (g *Geometry) courierEnvelopeReplyOverhead() int {
	const (
		envelopeHashLength    = hash.HashSize
		replyIndexLength      = 1
		errorCodeLength       = 1
		chachaPolyNonceLength = 12
		chachaPolyTagLength   = 16
		cborOverhead          = 20
	)

	return envelopeHashLength + replyIndexLength + errorCodeLength +
		chachaPolyNonceLength + chachaPolyTagLength + cborOverhead
}

func (g *Geometry) replicaInnerMessageOverhead() int {
	const (
		cborMapHeader                 = 1
		replicaReadKeyLen             = 12
		replicaWriteKeyLen            = 13
		nilValueOverhead              = 1
		cborFieldOverhead             = 2
		replicaWriteEmbeddingOverhead = 28

		unionStructOverhead = cborMapHeader + replicaReadKeyLen + replicaWriteKeyLen +
			nilValueOverhead + (2 * cborFieldOverhead)
	)

	replicaReadCaseOverhead := unionStructOverhead + g.replicaReadOverhead()
	replicaWriteCaseOverhead := unionStructOverhead + g.replicaWriteOverhead() + replicaWriteEmbeddingOverhead

	if replicaReadCaseOverhead > replicaWriteCaseOverhead {
		return replicaReadCaseOverhead
	}
	return replicaWriteCaseOverhead
}

func (g *Geometry) replicaReadOverhead() int {
	boxIDLength := g.SignatureScheme().PublicKeySize()
	cborOverhead := 9
	return boxIDLength + cborOverhead
}

func (g *Geometry) replicaWriteOverhead() int {
	const (
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
	tempGeo := &Geometry{
		BoxPayloadLength:    boxPayloadLength,
		NIKEName:            nikeScheme.Name(),
		SignatureSchemeName: SignatureSchemeName,
	}

	replicaReadSize := tempGeo.replicaReadOverhead()
	replicaInnerMessageReadSize := replicaInnerMessageOverheadForRead() + replicaReadSize

	replicaWriteSize := tempGeo.replicaWriteOverhead() + boxPayloadLength
	replicaInnerMessageWriteSize := replicaInnerMessageOverheadForWrite() + replicaWriteSize

	maxReplicaInnerMessageSize := max(replicaInnerMessageReadSize, replicaInnerMessageWriteSize)

	return tempGeo.courierEnvelopeOverhead() + mkemEncryptionOverhead(maxReplicaInnerMessageSize, nikeScheme)
}

func mkemEncryptionOverhead(plaintextSize int, nikeScheme nike.Scheme) int {
	const (
		chachaPolyNonceLength = 12
		chachaPolyTagLength   = 16
	)

	return nikeScheme.PublicKeySize() + chachaPolyNonceLength + chachaPolyTagLength + plaintextSize
}

func courierEnvelopeReplyLength(boxPayloadLength int) int {
	const (
		envelopeHashLength    = hash.HashSize
		replyIndexLength      = 1
		errorCodeLength       = 1
		chachaPolyNonceLength = 12
		chachaPolyTagLength   = 16
		cborOverhead          = 20
	)

	replicaReadReplyOverhead := replicaReadReplyOverhead()
	replicaWriteReplyOverhead := replicaWriteReplyOverhead()

	replicaReadReplySize := replicaReadReplyOverhead + boxPayloadLength
	replicaWriteReplySize := replicaWriteReplyOverhead

	replicaMessageReplyInnerOverhead := replicaMessageReplyInnerOverhead()
	maxReplicaMessageReplyInnerSize := max(
		replicaMessageReplyInnerOverhead + replicaReadReplySize,
		replicaMessageReplyInnerOverhead + replicaWriteReplySize,
	)

	return envelopeHashLength + replyIndexLength + errorCodeLength +
		chachaPolyNonceLength + chachaPolyTagLength + cborOverhead + maxReplicaMessageReplyInnerSize
}

func replicaInnerMessageOverheadForRead() int {
	const (
		cborMapHeader      = 1
		replicaReadKeyLen  = 12
		replicaWriteKeyLen = 13
		nilValueOverhead   = 1
		cborFieldOverhead  = 2

		unionStructOverhead = cborMapHeader + replicaReadKeyLen + replicaWriteKeyLen +
			nilValueOverhead + (2 * cborFieldOverhead)
	)
	return unionStructOverhead
}

func replicaInnerMessageOverheadForWrite() int {
	const (
		cborMapHeader                 = 1
		replicaReadKeyLen             = 12
		replicaWriteKeyLen            = 13
		nilValueOverhead              = 1
		cborFieldOverhead             = 2
		replicaWriteEmbeddingOverhead = 28

		unionStructOverhead = cborMapHeader + replicaReadKeyLen + replicaWriteKeyLen +
			nilValueOverhead + (2 * cborFieldOverhead)
	)
	return unionStructOverhead + replicaWriteEmbeddingOverhead
}

func replicaReadReplyOverhead() int {
	const (
		errorCodeLength   = 1
		boxIDLength       = 32
		signatureLength   = 64
		cborOverhead      = 15
	)
	return errorCodeLength + boxIDLength + signatureLength + cborOverhead
}

func replicaWriteReplyOverhead() int {
	const (
		errorCodeLength = 1
		cborOverhead    = 5
	)
	return errorCodeLength + cborOverhead
}

func replicaMessageReplyInnerOverhead() int {
	const (
		cborMapHeader           = 1
		replicaReadReplyKeyLen  = 16
		replicaWriteReplyKeyLen = 17
		nilValueOverhead        = 1
		cborFieldOverhead       = 2

		unionStructOverhead = cborMapHeader + replicaReadReplyKeyLen + replicaWriteReplyKeyLen +
			nilValueOverhead + (2 * cborFieldOverhead)
	)
	return unionStructOverhead
}

func calculateMaxBoxPayloadLength(maxCourierEnvelopeLength int, nikeScheme nike.Scheme) int {
	tempGeo := &Geometry{
		NIKEName:            nikeScheme.Name(),
		SignatureSchemeName: SignatureSchemeName,
	}

	courierOverhead := tempGeo.courierEnvelopeOverhead()
	mkemFixedOverhead := nikeScheme.PublicKeySize() + 12 + 16
	availableForReplicaInner := maxCourierEnvelopeLength - courierOverhead - mkemFixedOverhead

	readCaseOverhead := replicaInnerMessageOverheadForRead() + tempGeo.replicaReadOverhead()
	writeCaseFixedOverhead := replicaInnerMessageOverheadForWrite() + tempGeo.replicaWriteOverhead()

	if readCaseOverhead > availableForReplicaInner {
		return 0
	}

	maxBoxPayloadFromWriteCase := availableForReplicaInner - writeCaseFixedOverhead
	if maxBoxPayloadFromWriteCase < 0 {
		return 0
	}

	return maxBoxPayloadFromWriteCase
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
		CourierEnvelopeReplyLength: courierEnvelopeReplyLength(boxPayloadLength),
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

	maxPigeonholeMessageSize := pigeonholeGeometry.CourierEnvelopeLength
	return geo.GeometryFromUserForwardPayloadLength(nikeScheme, maxPigeonholeMessageSize, true, nrHops)
}

// GeometryFromSphinxGeometry solves Use Case 3: specify a precomputed SphinxGeometry as a
// size constraint and derive a PigeonholeGeometry object.
//
// This function takes an existing SphinxGeometry (perhaps constrained by network requirements)
// and determines the maximum BoxPayloadLength that can fit within the Sphinx packet size
// constraints. It then creates a PigeonholeGeometry that maximizes payload utilization
// while staying within the Sphinx limits. The signature scheme is always Ed25519 due to BACAP's dependency.
//
// Parameters:
//   - sphinxGeometry: An existing sphinx geometry that constrains the maximum message size
//   - nikeScheme: The NIKE scheme to use for MKEM encryption in the pigeonhole geometry
//
// Returns:
//   - *Geometry: The pigeonhole geometry with maximum BoxPayloadLength that fits the constraint
func GeometryFromSphinxGeometry(sphinxGeometry *geo.Geometry, nikeScheme nike.Scheme) *Geometry {
	maxPayloadSize := sphinxGeometry.UserForwardPayloadLength

	boxPayloadLength := calculateMaxBoxPayloadLength(maxPayloadSize, nikeScheme)
	if boxPayloadLength <= 0 {
		minRequired := courierEnvelopeLength(1, nikeScheme)
		panic(fmt.Sprintf("Sphinx geometry too small: UserForwardPayloadLength=%d, need at least %d",
			maxPayloadSize, minRequired))
	}

	return &Geometry{
		CourierEnvelopeLength:      courierEnvelopeLength(boxPayloadLength, nikeScheme),
		CourierEnvelopeReplyLength: courierEnvelopeReplyLength(boxPayloadLength),
		NIKEName:                   nikeScheme.Name(),
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
