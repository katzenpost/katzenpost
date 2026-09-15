// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package geo

import (
	"github.com/katzenpost/chacha20poly1305"
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
