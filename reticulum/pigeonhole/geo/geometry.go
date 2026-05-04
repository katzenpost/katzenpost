// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package geo computes the on-wire byte sizes for Pigeonhole-over-Reticulum
// queries and replies, composed from three layers:
//
//  1. The BACAP inner message (read or write request, plus its reply form).
//  2. The mKEM-encrypted ReplicaInnerMessage that wraps the BACAP layer.
//  3. The Reticulum-optimized CachedCourierEnvelope that wraps the mKEM
//     ciphertext, plus the existing pigeonhole CourierEnvelopeReply for
//     replies.
//  4. The classical Noise NK1 transport-phase AEAD tag added by the outer
//     mesh-client ↔ courier session, plus optional Reticulum carrier
//     wrapping when paired with a reticulum/geo Geometry.
//
// Mirrors the structure of katzenpost/pigeonhole/geo (the mixnet-side
// pigeonhole geometry) so the two protocols can be reasoned about with
// the same vocabulary.
package geo

import (
	"errors"
	"fmt"

	"github.com/katzenpost/chacha20poly1305"
	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/hybrid"

	rnsgeo "github.com/katzenpost/katzenpost/reticulum/geo"
	noisegeo "github.com/katzenpost/katzenpost/reticulum/noise/geo"
)

const (
	// signatureSchemeName is the BACAP signature scheme. Always Ed25519.
	signatureSchemeName = "Ed25519"

	// mkemDEKSize is the size of one mKEM Data Encryption Key.
	// Mirrors mkem.DEKSize (60 B = ChaCha20-Poly1305 wrap of a 32 B msgKey).
	mkemDEKSize = 60

	// mkemEncryptionOverhead is the byte overhead of mKEM payload
	// encryption: ChaCha20-Poly1305 nonce + AEAD tag.
	mkemEncryptionOverhead = chacha20poly1305.NonceSize + chacha20poly1305.Overhead

	// Trunnel field widths used in the cached_courier_envelope and the
	// existing courier_envelope_reply.
	cacheIDSize              = 16
	intermediateReplicasSize = 2
	replyIndexSize           = 1
	epochSize                = 8
	senderPubkeyLenSize      = 2
	ciphertextLenSize        = 4
	messageTypeSize          = 1
	errorCodeFieldSize       = 1
	payloadLenFieldSize      = 4
	envelopeHashSize         = 32
	replyTypeSize            = 1
)

// cachedEnvelopeFixedFraming is the byte length of all fixed-size and
// length-prefix fields in a CachedCourierEnvelope, excluding the
// optional sender_pubkey and the variable ciphertext.
//
//	cache_id (16) + intermediate_replicas (2) + dek1 (60) + dek2 (60)
//	+ reply_index (1) + epoch (8) + sender_pubkey_len (2)
//	+ ciphertext_len (4) = 153
const cachedEnvelopeFixedFraming = cacheIDSize + intermediateReplicasSize +
	mkemDEKSize + mkemDEKSize + replyIndexSize + epochSize +
	senderPubkeyLenSize + ciphertextLenSize

// courierEnvelopeReplyFraming is the fixed framing of the existing
// pigeonhole courier_envelope_reply (envelope_hash + reply_index +
// reply_type + payload_len + error_code = 32+1+1+4+1 = 39).
const courierEnvelopeReplyFraming = envelopeHashSize + replyIndexSize +
	replyTypeSize + payloadLenFieldSize + errorCodeFieldSize

// Geometry is the composed pigeonhole-over-reticulum sizing object.
//
// Use cases (mirroring katzenpost/pigeonhole/geo):
//
//  1. Given MaxPlaintextPayloadLength, NIKE scheme, and a paired Reticulum
//     Geometry → compute every envelope and carrier size.
//  2. Given a Reticulum Geometry constraint and a NIKE scheme → derive
//     the largest MaxPlaintextPayloadLength that fits.
//  3. Given a Geometry → derive an accommodating Reticulum Geometry
//     (work backwards through the layers).
type Geometry struct {
	// MaxPlaintextPayloadLength is the maximum BACAP-payload bytes
	// the geometry accommodates.
	MaxPlaintextPayloadLength int

	// CachedCourierEnvelopeWriteHit is the wire size of a write
	// envelope in cache-hit form (no inline pubkey).
	CachedCourierEnvelopeWriteHit int

	// CachedCourierEnvelopeWritePrime is the wire size of a write
	// envelope in cache-prime form (sender_pubkey inline = 160 B for
	// CTIDH1024-X25519).
	CachedCourierEnvelopeWritePrime int

	// CachedCourierEnvelopeReadHit / Prime: sizes for a read envelope.
	// Reads are fixed-size (the inner is just a BoxID), so payload
	// length doesn't enter into them.
	CachedCourierEnvelopeReadHit   int
	CachedCourierEnvelopeReadPrime int

	// CourierEnvelopeReplyWrite is the wire size of a reply to a write
	// query (small: just the BACAP write_reply error code and msg_type
	// inside the existing courier_envelope_reply).
	CourierEnvelopeReplyWrite int

	// CourierEnvelopeReplyRead is the wire size of a reply to a read
	// query (carries the BACAP-encrypted box payload).
	CourierEnvelopeReplyRead int

	// NoiseFramedSizeWriteHit is CachedCourierEnvelopeWriteHit + the
	// outer Noise NK1 transport AEAD tag (16 B). This is what the
	// Reticulum Link payload ultimately carries.
	NoiseFramedSizeWriteHit   int
	NoiseFramedSizeWritePrime int
	NoiseFramedSizeReadHit    int
	NoiseFramedSizeReadPrime  int
	NoiseFramedReplyWrite     int
	NoiseFramedReplyRead      int

	// Carrier-level wire bytes after Reticulum Link encryption (header
	// + IV + HMAC + AES-CBC ciphertext, summed over all fragments).
	// Computed when a Reticulum Geometry is supplied; zero otherwise.
	CarrierWireWriteHit   int
	CarrierWireWritePrime int
	CarrierWireReadHit    int
	CarrierWireReadPrime  int
	CarrierWireReplyWrite int
	CarrierWireReplyRead  int

	// Carrier fragment counts (number of Reticulum Link packets needed).
	CarrierFragmentsWriteHit   int
	CarrierFragmentsWritePrime int
	CarrierFragmentsReadHit    int
	CarrierFragmentsReadPrime  int
	CarrierFragmentsReplyWrite int
	CarrierFragmentsReplyRead  int

	// NIKEName is the name of the hybrid NIKE used for both mKEM
	// encryption and the outer Noise NK1 session.
	NIKEName string

	// SignatureSchemeName is the BACAP signature scheme (always
	// "Ed25519").
	SignatureSchemeName string
}

// DefaultNIKE is the hybrid NIKE used by NewGeometry's default path:
// CTIDH1024-X25519 (160 B public key). Matches the Noise NK1 default
// in reticulum/noise/geo and the mKEM scheme in the existing
// Pigeonhole protocol.
var DefaultNIKE = hybrid.CTIDH1024X25519

// NewGeometry constructs a Geometry from a target max BACAP payload
// length, a hybrid NIKE scheme, and (optionally) a Reticulum Geometry
// to derive carrier sizes from. Pass nil for rnsGeo to compute only
// envelope-level sizes.
func NewGeometry(maxPayload int, nikeScheme nike.Scheme, rnsGeo *rnsgeo.Geometry) *Geometry {
	if nikeScheme == nil {
		nikeScheme = DefaultNIKE
	}
	g := &Geometry{
		MaxPlaintextPayloadLength: maxPayload,
		NIKEName:                  nikeScheme.Name(),
		SignatureSchemeName:       signatureSchemeName,
	}
	g.fillEnvelopeSizes(nikeScheme.PublicKeySize())
	g.fillNoiseFramedSizes()
	if rnsGeo != nil {
		g.fillCarrierSizes(rnsGeo)
	}
	return g
}

// NewGeometryFromReticulum picks the largest MaxPlaintextPayloadLength
// that produces a write envelope (cache-hit form, including the outer
// Noise NK1 AEAD tag) fitting in a single Reticulum Link packet. Returns
// an error if even a zero-length payload doesn't fit.
//
// The returned Geometry has all fields populated, with carrier sizes
// computed against the supplied Reticulum Geometry.
func NewGeometryFromReticulum(rnsGeo *rnsgeo.Geometry, nikeScheme nike.Scheme) (*Geometry, error) {
	if nikeScheme == nil {
		nikeScheme = DefaultNIKE
	}
	if rnsGeo == nil {
		return nil, errors.New("pigeonhole/geo: NewGeometryFromReticulum requires a Reticulum Geometry")
	}

	budget := rnsGeo.EncryptedMDU(rnsgeo.EncryptionLink, true)
	noiseTag := noisegeo.AEADTagSize

	// fixed cost of a write envelope at payload N = cachedEnvelopeFixedFraming
	// + ciphertextN + noiseTag, where ciphertextN = 101 + N + mkemEncryptionOverhead.
	// (Cache-hit form, no inline pubkey.)
	fixedCost := cachedEnvelopeFixedFraming +
		writeInnerFixedOverhead() + mkemEncryptionOverhead +
		noiseTag

	maxPayload := budget - fixedCost
	if maxPayload < 0 {
		return nil, fmt.Errorf(
			"pigeonhole/geo: Reticulum EncryptedMDU(Link)=%d B too small to fit a zero-length write envelope (need >= %d B)",
			budget, fixedCost)
	}
	return NewGeometry(maxPayload, nikeScheme, rnsGeo), nil
}

// Validate checks the Geometry for internal consistency.
func (g *Geometry) Validate() error {
	if g.MaxPlaintextPayloadLength < 0 {
		return errors.New("pigeonhole/geo: MaxPlaintextPayloadLength must be non-negative")
	}
	if g.NIKEName == "" {
		return errors.New("pigeonhole/geo: NIKEName must be set")
	}
	if g.SignatureSchemeName != signatureSchemeName {
		return fmt.Errorf("pigeonhole/geo: SignatureSchemeName = %q, want %q",
			g.SignatureSchemeName, signatureSchemeName)
	}
	if g.NoiseFramedSizeWriteHit != g.CachedCourierEnvelopeWriteHit+noisegeo.AEADTagSize {
		return errors.New("pigeonhole/geo: NoiseFramedSizeWriteHit inconsistent with envelope+AEAD tag")
	}
	return nil
}

// String renders the geometry as a human-readable summary table.
func (g *Geometry) String() string {
	return fmt.Sprintf(
		"Pigeonhole-over-Reticulum Geometry\n"+
			"----------------------------------\n"+
			"Max BACAP payload          : %d bytes\n"+
			"NIKE scheme                : %s\n"+
			"Signature scheme           : %s\n"+
			"Cached envelope (write hit) : %d bytes\n"+
			"Cached envelope (write prime): %d bytes\n"+
			"Cached envelope (read hit)  : %d bytes\n"+
			"Cached envelope (read prime): %d bytes\n"+
			"Reply (write)              : %d bytes\n"+
			"Reply (read)               : %d bytes\n"+
			"Noise-framed (write hit)   : %d bytes\n"+
			"Noise-framed (read hit)    : %d bytes\n"+
			"Noise-framed reply (write) : %d bytes\n"+
			"Noise-framed reply (read)  : %d bytes\n"+
			"Carrier wire (write hit)   : %d bytes (%d frag)\n"+
			"Carrier wire (read hit)    : %d bytes (%d frag)\n",
		g.MaxPlaintextPayloadLength,
		g.NIKEName, g.SignatureSchemeName,
		g.CachedCourierEnvelopeWriteHit, g.CachedCourierEnvelopeWritePrime,
		g.CachedCourierEnvelopeReadHit, g.CachedCourierEnvelopeReadPrime,
		g.CourierEnvelopeReplyWrite, g.CourierEnvelopeReplyRead,
		g.NoiseFramedSizeWriteHit, g.NoiseFramedSizeReadHit,
		g.NoiseFramedReplyWrite, g.NoiseFramedReplyRead,
		g.CarrierWireWriteHit, g.CarrierFragmentsWriteHit,
		g.CarrierWireReadHit, g.CarrierFragmentsReadHit,
	)
}

// writeInnerFixedOverhead is the fixed bytes of a BACAP write inner
// message wrapping (msg_type discriminant + BoxID + Signature +
// payload_len), excluding the variable payload itself.
func writeInnerFixedOverhead() int {
	return messageTypeSize + bacap.BoxIDSize + bacap.SignatureSize + payloadLenFieldSize
}

// readInnerSize is the fixed bytes of a BACAP read inner message
// (msg_type discriminant + BoxID).
func readInnerSize() int {
	return messageTypeSize + bacap.BoxIDSize
}

// readReplyFixedOverhead is the fixed bytes of a BACAP read_reply
// inner message wrapping (msg_type + error_code + BoxID + Signature +
// payload_len), excluding the payload.
func readReplyFixedOverhead() int {
	return messageTypeSize + errorCodeFieldSize +
		bacap.BoxIDSize + bacap.SignatureSize + payloadLenFieldSize
}

// writeReplyFixedSize is the bytes of a BACAP write_reply inner
// message (msg_type + error_code), no variable parts.
const writeReplyFixedSize = messageTypeSize + errorCodeFieldSize

func (g *Geometry) fillEnvelopeSizes(pubkeySize int) {
	N := g.MaxPlaintextPayloadLength

	// mKEM-encrypted inner message ciphertext sizes.
	mkemWriteCiphertext := writeInnerFixedOverhead() + N + mkemEncryptionOverhead
	mkemReadCiphertext := readInnerSize() + mkemEncryptionOverhead
	mkemWriteReplyCiphertext := writeReplyFixedSize + mkemEncryptionOverhead
	mkemReadReplyCiphertext := readReplyFixedOverhead() + N + mkemEncryptionOverhead

	// Cached courier envelope sizes (cache-hit and cache-prime forms).
	g.CachedCourierEnvelopeWriteHit = cachedEnvelopeFixedFraming + mkemWriteCiphertext
	g.CachedCourierEnvelopeWritePrime = g.CachedCourierEnvelopeWriteHit + pubkeySize

	g.CachedCourierEnvelopeReadHit = cachedEnvelopeFixedFraming + mkemReadCiphertext
	g.CachedCourierEnvelopeReadPrime = g.CachedCourierEnvelopeReadHit + pubkeySize

	// Reply sizes use the existing pigeonhole courier_envelope_reply
	// shape, unchanged on this wire.
	g.CourierEnvelopeReplyWrite = courierEnvelopeReplyFraming + mkemWriteReplyCiphertext
	g.CourierEnvelopeReplyRead = courierEnvelopeReplyFraming + mkemReadReplyCiphertext
}

func (g *Geometry) fillNoiseFramedSizes() {
	tag := noisegeo.AEADTagSize
	g.NoiseFramedSizeWriteHit = g.CachedCourierEnvelopeWriteHit + tag
	g.NoiseFramedSizeWritePrime = g.CachedCourierEnvelopeWritePrime + tag
	g.NoiseFramedSizeReadHit = g.CachedCourierEnvelopeReadHit + tag
	g.NoiseFramedSizeReadPrime = g.CachedCourierEnvelopeReadPrime + tag
	g.NoiseFramedReplyWrite = g.CourierEnvelopeReplyWrite + tag
	g.NoiseFramedReplyRead = g.CourierEnvelopeReplyRead + tag
}

func (g *Geometry) fillCarrierSizes(rnsGeo *rnsgeo.Geometry) {
	const mode = rnsgeo.EncryptionLink
	const header2 = true

	g.CarrierWireWriteHit = rnsGeo.TotalWireBytes(g.NoiseFramedSizeWriteHit, mode, header2)
	g.CarrierWireWritePrime = rnsGeo.TotalWireBytes(g.NoiseFramedSizeWritePrime, mode, header2)
	g.CarrierWireReadHit = rnsGeo.TotalWireBytes(g.NoiseFramedSizeReadHit, mode, header2)
	g.CarrierWireReadPrime = rnsGeo.TotalWireBytes(g.NoiseFramedSizeReadPrime, mode, header2)
	g.CarrierWireReplyWrite = rnsGeo.TotalWireBytes(g.NoiseFramedReplyWrite, mode, header2)
	g.CarrierWireReplyRead = rnsGeo.TotalWireBytes(g.NoiseFramedReplyRead, mode, header2)

	g.CarrierFragmentsWriteHit = rnsGeo.FragmentsNeeded(g.NoiseFramedSizeWriteHit, mode, header2)
	g.CarrierFragmentsWritePrime = rnsGeo.FragmentsNeeded(g.NoiseFramedSizeWritePrime, mode, header2)
	g.CarrierFragmentsReadHit = rnsGeo.FragmentsNeeded(g.NoiseFramedSizeReadHit, mode, header2)
	g.CarrierFragmentsReadPrime = rnsGeo.FragmentsNeeded(g.NoiseFramedSizeReadPrime, mode, header2)
	g.CarrierFragmentsReplyWrite = rnsGeo.FragmentsNeeded(g.NoiseFramedReplyWrite, mode, header2)
	g.CarrierFragmentsReplyRead = rnsGeo.FragmentsNeeded(g.NoiseFramedReplyRead, mode, header2)
}
