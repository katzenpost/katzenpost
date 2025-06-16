// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/bacap"
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
// 1. specify BoxPayloadLength and derive appropriate Pigeonhole Geometry and Sphinx Geometry objects.
// 2. specify a precomputed Pigeonhole Geometry and derive accommodating Sphinx Geometry object.
// 3. specify a precomputed Sphinx Geometry as a size constraint and derive a Pigeonhole Geometry object.
type Geometry struct {

	// CourierQueryReadLength is the length of the CBOR serialized CourierQuery message for read operations.
	CourierQueryReadLength int

	// CourierQueryWriteLength is the length of the CBOR serialized CourierQuery message for write operations.
	CourierQueryWriteLength int

	// CourierQueryReplyReadLength is the length of the CBOR serialized CourierQueryReply message for read operations.
	CourierQueryReplyReadLength int

	// CourierQueryReplyWriteLength is the length of the CBOR serialized CourierQueryReply message for write operations.
	CourierQueryReplyWriteLength int

	// NikeName is the name of the NIKE scheme used by our MKEM scheme to encrypt
	// the CourierEnvelope and CourierEnvelopeReply messages.
	NIKEName string

	// SignatureSchemeName is the name of the signature scheme used
	// by BACAP to sign payloads.
	SignatureSchemeName string

	// BoxPayloadLength is the maximum size of actual user data that can be stored in a box.
	// This is the innermost payload size before the 4-byte length prefix and zero padding.
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
		BoxPayloadLength:             boxPayloadLength,
		SignatureSchemeName:          SignatureSchemeName,
		NIKEName:                     nikeScheme.Name(),
		CourierQueryReadLength:       courierQueryReadLength(boxPayloadLength, nikeScheme),
		CourierQueryWriteLength:      courierQueryWriteLength(boxPayloadLength, nikeScheme),
		CourierQueryReplyReadLength:  courierQueryReplyReadLength(boxPayloadLength),
		CourierQueryReplyWriteLength: courierQueryReplyWriteLength(boxPayloadLength),
	}
	return g
}

func (g *Geometry) courierEnvelopeReadOverhead() int {
	// Create a CourierEnvelope for read operations exactly like the real-world usage (measureCourierEnvelopeLayer)
	nikeScheme := g.NIKEScheme()

	// Create MKEM scheme and generate MKEM keys like real usage
	mkemScheme := mkem.NewScheme(nikeScheme)

	// Generate replica keys for MKEM (like real usage)
	replicaPubKeys := make([]nike.PublicKey, 2)
	for i := 0; i < 2; i++ {
		pub, _, err := nikeScheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		replicaPubKeys[i] = pub
	}

	// Create dummy plaintext to get MKEM keys
	dummyPlaintext := []byte("dummy")
	mkemPrivateKey, mkemCiphertext := mkemScheme.Encapsulate(replicaPubKeys, dummyPlaintext)
	mkemPublicKey := mkemPrivateKey.Public()

	// Calculate expected ciphertext size based on BoxPayloadLength for read operations
	expectedCiphertextSize := g.expectedMKEMCiphertextSizeForRead()
	testCiphertext := make([]byte, expectedCiphertextSize)

	envelope := &CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		ReplyIndex:           0,
		Epoch:                0,                     // Match real usage (defaults to 0)
		SenderEPubKey:        mkemPublicKey.Bytes(), // Use MKEM public key like real usage
		Ciphertext:           testCiphertext,
		IsRead:               true,
	}

	// Serialize and measure the overhead (total size minus ciphertext size)
	serialized := envelope.Bytes()
	return len(serialized) - len(testCiphertext)
}

func (g *Geometry) courierEnvelopeWriteOverhead(ciphertextSize int) int {
	// Create a CourierEnvelope for write operations exactly like the real-world usage (measureCourierEnvelopeLayer)
	nikeScheme := g.NIKEScheme()

	// Create MKEM scheme and generate MKEM keys like real usage
	mkemScheme := mkem.NewScheme(nikeScheme)

	// Generate replica keys for MKEM (like real usage)
	replicaPubKeys := make([]nike.PublicKey, 2)
	for i := 0; i < 2; i++ {
		pub, _, err := nikeScheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		replicaPubKeys[i] = pub
	}

	// Create dummy plaintext to get MKEM keys
	dummyPlaintext := []byte("dummy")
	mkemPrivateKey, mkemCiphertext := mkemScheme.Encapsulate(replicaPubKeys, dummyPlaintext)
	mkemPublicKey := mkemPrivateKey.Public()

	testCiphertext := make([]byte, ciphertextSize) // Use the actual expected ciphertext size

	envelope := &CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		ReplyIndex:           0,
		Epoch:                0,                     // Match real usage (defaults to 0)
		SenderEPubKey:        mkemPublicKey.Bytes(), // Use MKEM public key like real usage
		Ciphertext:           testCiphertext,
		IsRead:               false,
	}

	// Serialize and measure the overhead (total size minus ciphertext size)
	serialized := envelope.Bytes()
	return len(serialized) - len(testCiphertext)
}

func (g *Geometry) courierEnvelopeReplyOverhead() int {
	// Use the same calculation as the standalone function
	return calculateCourierEnvelopeReplyOverhead()
}

func (g *Geometry) replicaInnerMessageReadOverhead() int {
	// Use the same dynamic calculation as the standalone function
	return replicaInnerMessageOverheadForRead()
}

func (g *Geometry) replicaInnerMessageWriteOverhead() int {
	// Use the same dynamic calculation as the standalone function
	return replicaInnerMessageOverheadForWrite(g.BoxPayloadLength)
}

func (g *Geometry) replicaReadOverhead() int {
	boxIDLength := g.SignatureScheme().PublicKeySize()
	cborOverhead := 9
	return boxIDLength + cborOverhead
}

func (g *Geometry) replicaWriteOverhead() int {
	const (
		bacapEncryptionOverhead = 16
		isLastFieldSize         = 1
	)

	boxIDLength := g.SignatureScheme().PublicKeySize()
	signatureLength := g.SignatureScheme().SignatureSize()
	return commands.CmdOverhead + boxIDLength + signatureLength + isLastFieldSize + bacapEncryptionOverhead
}

func (g *Geometry) replicaWriteTotalOverhead() int {
	const (
		bacapEncryptionOverhead = 16
	)

	// ReplicaWrite uses binary wire protocol, not CBOR
	// Calculate actual overhead by creating a real ReplicaWrite message with BACAP-encrypted payload
	boxID := [bacap.BoxIDSize]byte{}
	signature := [bacap.SignatureSize]byte{}

	// Create a BACAP-encrypted payload using the geometry's PaddedPayloadLength
	// This represents the actual size that gets encrypted by BACAP (user data + 4-byte prefix)
	paddedPayload := make([]byte, g.PaddedPayloadLength())
	bacapEncryptedPayload := make([]byte, len(paddedPayload)+bacapEncryptionOverhead)
	copy(bacapEncryptedPayload, paddedPayload)

	writeRequest := commands.ReplicaWrite{
		BoxID:     &boxID,
		Signature: &signature,
		Payload:   bacapEncryptedPayload,
	}

	actualSize := len(writeRequest.ToBytes())
	bacapEncryptedSize := len(bacapEncryptedPayload)

	// ReplicaWrite wire overhead = total size - BACAP encrypted payload size
	wireOverhead := actualSize - bacapEncryptedSize

	// For the geometry calculation, we need to return the total overhead relative to padded payload
	// This function is used as: replicaWriteSize = replicaWriteTotalOverhead() + paddedPayloadLength
	// So it should return: wire overhead + BACAP encryption overhead
	return wireOverhead + bacapEncryptionOverhead
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
		return errors.New("geometry BoxPayloadLength is not set")
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

// PaddedPayloadLength returns the total size of the BACAP payload after adding
// the 4-byte length prefix and zero padding. This is the size that gets encrypted by BACAP.
func (g *Geometry) PaddedPayloadLength() int {
	const lengthPrefixSize = 4
	return g.BoxPayloadLength + lengthPrefixSize
}

// ExpectedMKEMCiphertextSizeForWrite returns the expected size of the MKEM ciphertext
// for write operations. This ensures BACAP payloads are padded to the maximum size.
func (g *Geometry) ExpectedMKEMCiphertextSizeForWrite() int {
	// Calculate the size of ReplicaWrite with BACAP payload padded to PaddedPayloadLength
	// This includes the user data + 4-byte length prefix
	replicaWriteSize := g.replicaWriteTotalOverhead() + g.PaddedPayloadLength()

	// Add ReplicaInnerMessage wrapper overhead
	replicaInnerMessageWriteSize := replicaInnerMessageOverheadForWrite(g.BoxPayloadLength) + replicaWriteSize

	// Add MKEM encryption overhead (ChaCha20-Poly1305)
	return mkemCiphertextSize(replicaInnerMessageWriteSize)
}

// expectedMKEMCiphertextSizeForRead returns the expected size of the MKEM ciphertext
// for read operations based on the BoxPayloadLength.
func (g *Geometry) expectedMKEMCiphertextSizeForRead() int {
	// Calculate the size of ReplicaRead
	replicaReadSize := g.replicaReadOverhead()

	// Add ReplicaInnerMessage wrapper overhead
	replicaInnerMessageReadSize := replicaInnerMessageOverheadForRead() + replicaReadSize

	// Add MKEM encryption overhead (ChaCha20-Poly1305)
	return mkemCiphertextSize(replicaInnerMessageReadSize)
}

func (g *Geometry) String() string {
	var b strings.Builder
	b.WriteString("pigeonhole_geometry:\n")
	b.WriteString(fmt.Sprintf("CourierQueryReadLength: %d\n", g.CourierQueryReadLength))
	b.WriteString(fmt.Sprintf("CourierQueryWriteLength: %d\n", g.CourierQueryWriteLength))
	b.WriteString(fmt.Sprintf("CourierQueryReplyReadLength: %d\n", g.CourierQueryReplyReadLength))
	b.WriteString(fmt.Sprintf("CourierQueryReplyWriteLength: %d\n", g.CourierQueryReplyWriteLength))
	b.WriteString(fmt.Sprintf("NIKEName: %s\n", g.NIKEName))
	b.WriteString(fmt.Sprintf("SignatureSchemeName: %s\n", g.SignatureSchemeName))
	b.WriteString(fmt.Sprintf("BoxPayloadLength: %d\n", g.BoxPayloadLength))
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

func courierQueryReadLength(boxPayloadLength int, nikeScheme nike.Scheme) int {
	tempGeo := &Geometry{
		BoxPayloadLength:    boxPayloadLength,
		NIKEName:            nikeScheme.Name(),
		SignatureSchemeName: SignatureSchemeName,
	}

	replicaReadSize := tempGeo.replicaReadOverhead()
	replicaInnerMessageReadSize := replicaInnerMessageOverheadForRead() + replicaReadSize

	courierOverhead := tempGeo.courierEnvelopeReadOverhead()
	mkemCiphertext := mkemCiphertextSize(replicaInnerMessageReadSize)
	courierEnvelopeSize := courierOverhead + mkemCiphertext

	// Calculate CourierQuery wrapper overhead dynamically using the same NIKE scheme
	courierQueryWrapperOverhead := calculateCourierQueryWrapperOverhead(courierEnvelopeSize, nikeScheme)

	return courierEnvelopeSize + courierQueryWrapperOverhead
}

func courierQueryWriteLength(boxPayloadLength int, nikeScheme nike.Scheme) int {
	tempGeo := &Geometry{
		BoxPayloadLength:    boxPayloadLength,
		NIKEName:            nikeScheme.Name(),
		SignatureSchemeName: SignatureSchemeName,
	}

	// Use the padded payload length (user data + 4-byte prefix) for write operations
	replicaWriteSize := tempGeo.replicaWriteTotalOverhead() + tempGeo.PaddedPayloadLength()
	replicaInnerMessageWriteSize := replicaInnerMessageOverheadForWrite(boxPayloadLength) + replicaWriteSize

	// Calculate MKEM ciphertext size first
	mkemCiphertext := mkemCiphertextSize(replicaInnerMessageWriteSize)

	// Now calculate courier overhead using the actual ciphertext size
	courierOverhead := tempGeo.courierEnvelopeWriteOverhead(mkemCiphertext)
	courierEnvelopeSize := courierOverhead + mkemCiphertext

	// Calculate CourierQuery wrapper overhead dynamically using the same NIKE scheme
	courierQueryWrapperOverhead := calculateCourierQueryWrapperOverhead(courierEnvelopeSize, nikeScheme)

	return courierEnvelopeSize + courierQueryWrapperOverhead
}

// calculateCourierQueryWrapperOverhead dynamically calculates the CBOR overhead for CourierQuery wrapper
func calculateCourierQueryWrapperOverhead(courierEnvelopeSize int, nikeScheme nike.Scheme) int {
	// Create a CourierEnvelope with the EXACT size that will be encapsulated, using real-world MKEM keys

	// Create MKEM scheme and generate MKEM keys like real-world usage
	mkemScheme := mkem.NewScheme(nikeScheme)

	// Generate replica keys for MKEM (like real usage)
	replicaPubKeys := make([]nike.PublicKey, 2)
	for i := 0; i < 2; i++ {
		pub, _, err := nikeScheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		replicaPubKeys[i] = pub
	}

	// Create dummy plaintext to get MKEM keys
	dummyPlaintext := []byte("dummy")
	mkemPrivateKey, mkemCiphertext := mkemScheme.Encapsulate(replicaPubKeys, dummyPlaintext)
	mkemPublicKey := mkemPrivateKey.Public()

	// Calculate the ciphertext size that would result in the target courierEnvelopeSize
	// We need to work backwards: courierEnvelopeSize = overhead + ciphertext
	// So: ciphertext = courierEnvelopeSize - overhead

	// First, create a minimal envelope to measure its overhead
	minimalEnvelope := &CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		ReplyIndex:           0,
		Epoch:                0,                     // Use consistent epoch for predictable geometry calculations
		SenderEPubKey:        mkemPublicKey.Bytes(), // Use MKEM public key like real usage
		Ciphertext:           []byte{},              // Empty to measure overhead
		IsRead:               false,
	}

	envelopeOverhead := len(minimalEnvelope.Bytes())
	ciphertextSize := courierEnvelopeSize - envelopeOverhead

	// Now create the envelope with the correct ciphertext size
	ciphertext := make([]byte, ciphertextSize)
	courierEnvelope := &CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		ReplyIndex:           0,
		Epoch:                0,                     // Use consistent epoch for predictable geometry calculations
		SenderEPubKey:        mkemPublicKey.Bytes(), // Use MKEM public key like real usage
		Ciphertext:           ciphertext,
		IsRead:               false,
	}

	// Create the CourierQuery wrapper
	courierQuery := &CourierQuery{
		CourierEnvelope: courierEnvelope,
		CopyCommand:     nil,
	}

	// Calculate the wrapper overhead
	totalSize := len(courierQuery.Bytes())
	envelopeSize := len(courierEnvelope.Bytes())

	return totalSize - envelopeSize
}

func mkemCiphertextSize(plaintextSize int) int {
	const (
		chachaPolyNonceLength = 12
		chachaPolyTagLength   = 16
	)

	return chachaPolyNonceLength + chachaPolyTagLength + plaintextSize
}

func courierQueryReplyReadLength(boxPayloadLength int) int {
	const (
		bacapEncryptionOverhead = 16
		lengthPrefixSize        = 4
	)

	// Calculate the padded payload length (user data + 4-byte prefix)
	paddedPayloadLength := boxPayloadLength + lengthPrefixSize

	replicaReadReplyOverhead := replicaReadReplyOverhead()
	replicaReadReplySize := replicaReadReplyOverhead + paddedPayloadLength + bacapEncryptionOverhead

	replicaMessageReplyInnerOverhead := replicaMessageReplyInnerOverhead()
	replicaMessageReplyInnerSize := replicaMessageReplyInnerOverhead + replicaReadReplySize

	// The Payload field contains MKEM-encrypted ReplicaMessageReplyInnerMessage
	mkemCiphertext := mkemCiphertextSize(replicaMessageReplyInnerSize)
	courierEnvelopeReplySize := calculateCourierEnvelopeReplyOverhead() + mkemCiphertext

	// Calculate CourierQueryReply wrapper overhead dynamically
	courierQueryReplyWrapperOverhead := calculateCourierQueryReplyWrapperOverhead(courierEnvelopeReplySize)

	return courierEnvelopeReplySize + courierQueryReplyWrapperOverhead
}

func courierQueryReplyWriteLength(boxPayloadLength int) int {
	replicaWriteReplyOverhead := replicaWriteReplyOverhead()
	replicaWriteReplySize := replicaWriteReplyOverhead

	replicaMessageReplyInnerOverhead := replicaMessageReplyInnerOverhead()
	replicaMessageReplyInnerSize := replicaMessageReplyInnerOverhead + replicaWriteReplySize

	// The Payload field contains MKEM-encrypted ReplicaMessageReplyInnerMessage
	mkemCiphertext := mkemCiphertextSize(replicaMessageReplyInnerSize)
	courierEnvelopeReplySize := calculateCourierEnvelopeReplyOverhead() + mkemCiphertext

	// Calculate CourierQueryReply wrapper overhead dynamically
	courierQueryReplyWrapperOverhead := calculateCourierQueryReplyWrapperOverhead(courierEnvelopeReplySize)

	return courierEnvelopeReplySize + courierQueryReplyWrapperOverhead
}

// calculateCourierEnvelopeReplyOverhead dynamically calculates the CBOR overhead for CourierEnvelopeReply
func calculateCourierEnvelopeReplyOverhead() int {
	// Create a CourierEnvelopeReply with a reasonable test payload to measure CBOR overhead
	// Use a moderate size that represents typical MKEM ciphertext sizes
	testPayload := make([]byte, 500)
	envelopeHash := &[hash.HashSize]byte{}

	reply := &CourierEnvelopeReply{
		EnvelopeHash: envelopeHash,
		ReplyIndex:   0,
		ErrorCode:    0,
		Payload:      testPayload,
	}

	// Serialize and measure the overhead (total size minus payload size)
	serialized := reply.Bytes()
	return len(serialized) - len(testPayload)
}

// calculateCourierQueryReplyWrapperOverhead dynamically calculates the CBOR overhead for CourierQueryReply wrapper
func calculateCourierQueryReplyWrapperOverhead(courierEnvelopeReplySize int) int {
	// Calculate the payload size that would result in the target courierEnvelopeReplySize
	// We need to work backwards: courierEnvelopeReplySize = overhead + payload
	// So: payload = courierEnvelopeReplySize - overhead

	// First, create a minimal envelope reply to measure its overhead
	envelopeHash := &[hash.HashSize]byte{}
	minimalReply := &CourierEnvelopeReply{
		EnvelopeHash: envelopeHash,
		ReplyIndex:   0,
		ErrorCode:    0,
		Payload:      []byte{}, // Empty to measure overhead
	}

	replyOverhead := len(minimalReply.Bytes())
	payloadSize := courierEnvelopeReplySize - replyOverhead

	// Now create the envelope reply with the correct payload size
	payload := make([]byte, payloadSize)
	courierEnvelopeReply := &CourierEnvelopeReply{
		EnvelopeHash: envelopeHash,
		ReplyIndex:   0,
		ErrorCode:    0,
		Payload:      payload,
	}

	// Create the CourierQueryReply wrapper
	courierQueryReply := &CourierQueryReply{
		CourierEnvelopeReply: courierEnvelopeReply,
		CopyCommandReply:     nil,
	}

	// Calculate the wrapper overhead
	totalSize := len(courierQueryReply.Bytes())
	envelopeReplySize := len(courierEnvelopeReply.Bytes())

	return totalSize - envelopeReplySize
}

func replicaInnerMessageOverheadForRead() int {
	// Create a real ReplicaRead to measure actual CBOR overhead
	boxID := [bacap.BoxIDSize]byte{}

	readRequest := ReplicaRead{
		BoxID: &boxID,
	}

	// Create ReplicaInnerMessage containing the ReplicaRead
	msg := &ReplicaInnerMessage{
		ReplicaRead:  &readRequest,
		ReplicaWrite: nil, // Only one field should be set
	}

	// Measure the actual CBOR overhead
	totalSize := len(msg.Bytes())
	replicaReadSize := len(readRequest.ToBytes())

	return totalSize - replicaReadSize
}

func replicaInnerMessageOverheadForWrite(boxPayloadLength int) int {
	// Use the actual BoxPayloadLength for accurate overhead calculation

	// Create test data and pad it using the new helper function
	testData := []byte("test data for overhead calculation")
	paddedPayload, err := CreatePaddedPayload(testData, boxPayloadLength)
	if err != nil {
		panic(err)
	}

	owner, err := bacap.NewBoxOwnerCap(rand.Reader)
	if err != nil {
		panic(err)
	}

	ctx := []byte("test context")
	statefulWriter, err := bacap.NewStatefulWriter(owner, ctx)
	if err != nil {
		panic(err)
	}

	// BACAP encrypt the padded payload exactly like the test
	boxID, ciphertext, sigraw, err := statefulWriter.EncryptNext(paddedPayload)
	if err != nil {
		panic(err)
	}

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	// Create ReplicaWrite exactly like the test
	writeRequest := commands.ReplicaWrite{
		BoxID:     &boxID,
		Signature: &sig,
		Payload:   ciphertext,
	}

	// Create ReplicaInnerMessage containing the ReplicaWrite
	msg := &ReplicaInnerMessage{
		ReplicaWrite: &writeRequest,
		ReplicaRead:  nil, // Only one field should be set
	}

	// Measure the actual CBOR overhead
	totalSize := len(msg.Bytes())
	replicaWriteSize := len(writeRequest.ToBytes())

	return totalSize - replicaWriteSize
}

func replicaReadReplyOverhead() int {
	// Create a ReplicaReadReply with a test payload to measure CBOR overhead exactly like the test
	testPayload := make([]byte, 100)
	boxID := [bacap.BoxIDSize]byte{}
	signature := [bacap.SignatureSize]byte{}

	reply := &ReplicaReadReply{
		ErrorCode: 0,
		BoxID:     &boxID,
		Signature: &signature,
		Payload:   testPayload,
		IsLast:    false,
	}

	// Serialize and measure the overhead (total size minus payload size)
	serialized := reply.Bytes()
	return len(serialized) - len(testPayload)
}

func replicaWriteReplyOverhead() int {
	// Create a minimal ReplicaWriteReply to measure CBOR overhead
	reply := &commands.ReplicaWriteReply{
		ErrorCode: 0,
	}

	// Serialize and measure the overhead
	serialized := reply.ToBytes()
	return len(serialized)
}

func replicaMessageReplyInnerOverhead() int {
	// Create a ReplicaMessageReplyInnerMessage to measure CBOR overhead
	// We'll use the write case since it's smaller (no payload)
	writeReply := &commands.ReplicaWriteReply{
		ErrorCode: 0,
	}

	innerMsg := &ReplicaMessageReplyInnerMessage{
		ReplicaReadReply:  nil, // This is correct - only one field should be set
		ReplicaWriteReply: writeReply,
	}

	// Serialize and measure the overhead (everything except the actual reply content)
	serialized := innerMsg.Bytes()
	writeReplySize := len(writeReply.ToBytes())

	// Return the overhead (total size minus the embedded reply size)
	return len(serialized) - writeReplySize
}

func calculateMaxBoxPayloadLength(maxCourierQueryLength int, nikeScheme nike.Scheme) int {
	// Pure arithmetic calculation - no iteration needed
	// Solve: maxCourierQueryLength = totalFixedOverhead + BoxPayloadLength + lengthPrefixSize

	const (
		lengthPrefixSize        = 4  // 4-byte length prefix in BACAP payload
		bacapEncryptionOverhead = 16 // BACAP encryption overhead
		mkemOverhead            = 28 // ChaCha20-Poly1305: 12 nonce + 16 tag
	)

	// Get signature scheme overhead (static)
	signatureScheme := signSchemes.ByName(SignatureSchemeName)
	if signatureScheme == nil {
		panic("failed to get signature scheme")
	}
	boxIDLength := signatureScheme.PublicKeySize()
	signatureLength := signatureScheme.SignatureSize()

	// Calculate all static overheads
	replicaWriteStaticOverhead := commands.CmdOverhead + boxIDLength + signatureLength + 1 + bacapEncryptionOverhead // +1 for IsLast field

	// Calculate CBOR overheads using minimal test data (these are nearly constant)
	replicaInnerMessageOverhead := replicaInnerMessageOverheadForWrite(100) // Use small test size - overhead is nearly constant

	// Create a temporary geometry to use existing overhead calculation methods
	tempGeo := &Geometry{
		BoxPayloadLength:    100, // Use small test size for overhead calculation
		NIKEName:            nikeScheme.Name(),
		SignatureSchemeName: SignatureSchemeName,
	}

	// Calculate CourierEnvelope overhead using existing method
	testMkemCiphertextSize := mkemCiphertextSize(100) // Small test size
	courierEnvelopeOverhead := tempGeo.courierEnvelopeWriteOverhead(testMkemCiphertextSize)

	// Calculate CourierQuery wrapper overhead using existing method
	courierQueryWrapperOverhead := calculateCourierQueryWrapperOverhead(testMkemCiphertextSize+courierEnvelopeOverhead, nikeScheme)

	// Total fixed overhead = all overhead except the variable BoxPayloadLength + lengthPrefixSize
	totalFixedOverhead := replicaWriteStaticOverhead + replicaInnerMessageOverhead +
		mkemOverhead + courierEnvelopeOverhead + courierQueryWrapperOverhead

	// Solve: maxCourierQueryLength = totalFixedOverhead + BoxPayloadLength + lengthPrefixSize
	// Therefore: BoxPayloadLength = maxCourierQueryLength - totalFixedOverhead - lengthPrefixSize
	maxBoxPayloadLength := maxCourierQueryLength - totalFixedOverhead - lengthPrefixSize

	// Add small safety margin for CBOR encoding variations (CBOR can vary by 1-2 bytes)
	const cborSafetyMargin = 3
	maxBoxPayloadLength -= cborSafetyMargin

	if maxBoxPayloadLength <= 0 {
		return 0
	}

	return maxBoxPayloadLength
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
		CourierQueryReadLength:       courierQueryReadLength(boxPayloadLength, nikeScheme),
		CourierQueryWriteLength:      courierQueryWriteLength(boxPayloadLength, nikeScheme),
		CourierQueryReplyReadLength:  courierQueryReplyReadLength(boxPayloadLength),
		CourierQueryReplyWriteLength: courierQueryReplyWriteLength(boxPayloadLength),
		NIKEName:                     nikeScheme.Name(),
		SignatureSchemeName:          SignatureSchemeName,
		BoxPayloadLength:             boxPayloadLength,
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

	maxPigeonholeMessageSize := max(pigeonholeGeometry.CourierQueryReadLength, pigeonholeGeometry.CourierQueryWriteLength)
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
		minRequired := max(courierQueryReadLength(1, nikeScheme), courierQueryWriteLength(1, nikeScheme))
		panic(fmt.Sprintf("Sphinx geometry too small: UserForwardPayloadLength=%d, need at least %d",
			maxPayloadSize, minRequired))
	}

	return &Geometry{
		CourierQueryReadLength:       courierQueryReadLength(boxPayloadLength, nikeScheme),
		CourierQueryWriteLength:      courierQueryWriteLength(boxPayloadLength, nikeScheme),
		CourierQueryReplyReadLength:  courierQueryReplyReadLength(boxPayloadLength),
		CourierQueryReplyWriteLength: courierQueryReplyWriteLength(boxPayloadLength),
		NIKEName:                     nikeScheme.Name(),
		SignatureSchemeName:          SignatureSchemeName,
		BoxPayloadLength:             boxPayloadLength,
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
