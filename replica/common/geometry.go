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
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

const (
	SignatureSchemeName = "Ed25519"
)

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

func NewGeometry(boxPayloadLength int) *Geometry {
	return &Geometry{
		BoxPayloadLength:    boxPayloadLength,
		SignatureSchemeName: SignatureSchemeName,
		NIKEName:            NikeScheme.Name(),
	}
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
// Based on empirical measurements, we break down the overhead into constituent parts.
func (g *Geometry) replicaInnerMessageOverhead() int {
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

	// ReplicaRead case: union overhead + embedded ReplicaRead CBOR overhead
	// ReplicaRead is a struct with one field (BoxID) that gets CBOR serialized
	replicaReadEmbeddedOverhead := 1 + 6 + 1 + 32 // CBOR map + "BoxID" key + field overhead + BoxID size
	replicaReadCaseOverhead := unionStructOverhead + replicaReadEmbeddedOverhead

	// ReplicaWrite case: union overhead + embedded ReplicaWrite CBOR overhead
	// ReplicaWrite gets CBOR serialized with all its fields
	replicaWriteEmbeddedOverhead := 1 + 5 + 1 + 32 + 1 + 9 + 1 + 64 + 1 + 7 + 1 // CBOR overhead for all ReplicaWrite fields
	replicaWriteCaseOverhead := unionStructOverhead + replicaWriteEmbeddedOverhead

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
	boxIDLength := g.SignatureScheme().PublicKeySize()
	signatureLength := g.SignatureScheme().SignatureSize()
	return commands.CmdOverhead + boxIDLength + signatureLength
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

func init() {
	var err error
	opts := cbor.CanonicalEncOptions()
	ccbor, err = opts.EncMode()
	if err != nil {
		panic(err)
	}
}
