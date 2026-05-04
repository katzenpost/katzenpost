// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package geo models the on-wire byte sizes of a classical Noise NK1
// session over a NIKE primitive (defaulting to the CTIDH512-X25519
// hybrid NIKE).
//
// The two facts this geometry exposes are:
//
//   1. Each handshake message's size, so callers can ask whether each
//      one fits in a single Reticulum Link packet.
//   2. The per-message transport-phase overhead (AEAD tag plus any
//      framing applied around the Noise messages), which is constant
//      after the handshake completes.
//
// The NK1 pattern (deferred variant of NK), from `nyquist`'s
// pattern/deferred.go:
//
//	NK1:
//	  <- s          (pre-message: responder static is pre-shared)
//	  ...
//	  -> e          (msg1: just initiator's ephemeral pubkey, no key yet)
//	  <- e, ee, es  (msg2: responder's ephemeral; both ee and es computed)
//
// The pattern is one-way authenticated: the initiator authenticates
// the responder via es (only the holder of rs's secret can decap), and
// gains forward secrecy from ee. The initiator stays anonymous: no
// initiator static is involved.
//
// Why NK1 instead of NK. NK1 saves the 16 B AEAD tag on msg1 because
// no key is established yet at the point msg1 is written. The trade
// is that NK1 has no 0-RTT capability on msg1; we never relied on
// 0-RTT in the design, so this is pure savings.
//
// Why classical Noise NK1 instead of pqNK1. CTIDH512-X25519 is a
// NIKE. Classical Noise's NIKE-style patterns let `es` and `ee` be
// computed locally on both sides via NIKE commutativity, so they
// don't need to be transmitted as ciphertexts. PQ Noise (designed for
// non-NIKE KEMs) would require a separate ciphertext for each KEM
// operation, paying ~96 B per extra ciphertext on the wire.
package geo

import (
	"errors"
	"fmt"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/hybrid"

	rnsgeo "github.com/katzenpost/katzenpost/reticulum/geo"
)

// AEAD parameters for the Noise cipher suite (ChaCha20-Poly1305).
const (
	// AEADTagSize is the byte length of the ChaCha20-Poly1305 tag
	// appended to every encrypted Noise message. There is no on-wire
	// nonce because Noise's transport-phase nonce is an implicit
	// counter, advanced on each Encrypt/Decrypt.
	AEADTagSize = 16
)

// DefaultNIKE is the NIKE scheme used by New(): CTIDH1024 + X25519
// hybrid. CTIDH1024 has a 128 B public key, X25519 has a 32 B public
// key, the hybrid is 160 B. Matches the NIKE used for mKEM in the
// existing Pigeonhole protocol so the two cryptographic layers
// (Noise NK1 and mKEM) share key material.
var DefaultNIKE = hybrid.CTIDH1024X25519

// Geometry describes the byte sizes of a Noise NK1 session over a
// chosen NIKE.
type Geometry struct {
	// NIKESchemeName is the Name() of the NIKE scheme, e.g.
	// "CTIDH512-X25519".
	NIKESchemeName string

	// PublicKeySize is the byte length of one NIKE public key. For
	// the hybrid NIKE this is the sum of the component sizes.
	PublicKeySize int

	// AEADTagSize is the per-message AEAD tag length (16 B for
	// ChaCha20-Poly1305).
	AEADTagSize int

	// NoiseFramingOverhead is any extra per-message overhead applied
	// around a Noise message by the surrounding transport. For our
	// setting (one Noise message per Reticulum Link packet, or one
	// Noise message per length-prefixed trunnel CourierHandshake),
	// the surrounding transport supplies its own framing and we add
	// none, so this is 0.
	NoiseFramingOverhead int
}

// New returns a Geometry for the default NIKE (CTIDH512-X25519).
func New() *Geometry {
	return NewWithScheme(DefaultNIKE)
}

// NewWithScheme returns a Geometry for an arbitrary hpqc NIKE scheme.
func NewWithScheme(nikeScheme nike.Scheme) *Geometry {
	return &Geometry{
		NIKESchemeName:       nikeScheme.Name(),
		PublicKeySize:        nikeScheme.PublicKeySize(),
		AEADTagSize:          AEADTagSize,
		NoiseFramingOverhead: 0,
	}
}

// Validate returns an error if the Geometry is internally
// inconsistent.
func (g *Geometry) Validate() error {
	if g.PublicKeySize <= 0 {
		return errors.New("noise/geo: public key size must be positive")
	}
	if g.AEADTagSize <= 0 {
		return errors.New("noise/geo: AEAD tag size must be positive")
	}
	if g.NoiseFramingOverhead < 0 {
		return errors.New("noise/geo: framing overhead must be non-negative")
	}
	if g.NIKESchemeName == "" {
		return errors.New("noise/geo: NIKE scheme name must not be empty")
	}
	return nil
}

// HandshakeMsg1Size returns the byte length of the NK1 first
// handshake message (initiator → responder). msg1 carries just the
// initiator's ephemeral public key, with no AEAD tag because no key
// has been established at the point msg1 is written.
func (g *Geometry) HandshakeMsg1Size() int {
	return g.PublicKeySize + g.NoiseFramingOverhead
}

// HandshakeMsg2Size returns the byte length of the NK1 second
// handshake message (responder → initiator). msg2 carries the
// responder's ephemeral public key plus an AEAD tag (an empty
// payload encrypted under the chain key established by ee + es).
func (g *Geometry) HandshakeMsg2Size() int {
	return g.PublicKeySize + g.AEADTagSize + g.NoiseFramingOverhead
}

// HandshakeTotalSize returns the total bytes exchanged during the
// handshake.
func (g *Geometry) HandshakeTotalSize() int {
	return g.HandshakeMsg1Size() + g.HandshakeMsg2Size()
}

// TransportPerMessageOverhead returns the bytes added on top of every
// transport-phase plaintext: the AEAD tag plus any framing.
func (g *Geometry) TransportPerMessageOverhead() int {
	return g.AEADTagSize + g.NoiseFramingOverhead
}

// TransportCiphertextSize returns the wire byte length of a
// transport-phase Noise message that wraps plaintextLen bytes of
// plaintext.
func (g *Geometry) TransportCiphertextSize(plaintextLen int) int {
	if plaintextLen < 0 {
		return 0
	}
	return plaintextLen + g.TransportPerMessageOverhead()
}

// FitsInLinkPacket reports whether each handshake message fits in a
// single Link-encrypted Reticulum packet for the given Reticulum
// Geometry. header2 selects HEADER_2 (in-transport, two destination
// hashes); pass true for the conservative case.
func (g *Geometry) FitsInLinkPacket(rnsGeo *rnsgeo.Geometry, header2 bool) (msg1Fits, msg2Fits bool) {
	budget := rnsGeo.EncryptedMDU(rnsgeo.EncryptionLink, header2)
	msg1Fits = g.HandshakeMsg1Size() <= budget
	msg2Fits = g.HandshakeMsg2Size() <= budget
	return
}

// HandshakeFragmentsNeeded returns the number of Reticulum Link
// fragments each handshake message takes for the given Reticulum
// Geometry.
func (g *Geometry) HandshakeFragmentsNeeded(rnsGeo *rnsgeo.Geometry, header2 bool) (msg1Frags, msg2Frags int) {
	msg1Frags = rnsGeo.FragmentsNeeded(g.HandshakeMsg1Size(), rnsgeo.EncryptionLink, header2)
	msg2Frags = rnsGeo.FragmentsNeeded(g.HandshakeMsg2Size(), rnsgeo.EncryptionLink, header2)
	return
}

// String implements fmt.Stringer.
func (g *Geometry) String() string {
	return fmt.Sprintf(
		"Noise NK1 Geometry\n"+
			"------------------\n"+
			"NIKE scheme            : %s\n"+
			"Public key size        : %d bytes\n"+
			"AEAD tag size          : %d bytes\n"+
			"Noise framing overhead : %d bytes\n"+
			"Handshake msg1 size    : %d bytes\n"+
			"Handshake msg2 size    : %d bytes\n"+
			"Handshake total        : %d bytes\n"+
			"Transport per-message  : %d bytes\n",
		g.NIKESchemeName,
		g.PublicKeySize,
		g.AEADTagSize,
		g.NoiseFramingOverhead,
		g.HandshakeMsg1Size(),
		g.HandshakeMsg2Size(),
		g.HandshakeTotalSize(),
		g.TransportPerMessageOverhead(),
	)
}
