/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/agl/ed25519/extra25519"
	"github.com/katzenpost/core/crypto/rand"
	"golang.org/x/crypto/curve25519"
)

const (
	// PublicKeyLength is the length of a Curve25519 public key.
	PublicKeyLength = 32

	// RepresentativeLength is the length of an Elligator representative.
	RepresentativeLength = 32

	// PrivateKeyLength is the length of a Curve25519 private key.
	PrivateKeyLength = 32

	// SharedSecretLength is the length of a Curve25519 shared secret.
	SharedSecretLength = 32

	// GroupElementLength is the length of a ECDH group element in bytes.
	GroupElementLength = PublicKeyLength
)

// PublicKeyLengthError is the error returned when the public key being
// imported is an invalid length.
type PublicKeyLengthError int

func (e PublicKeyLengthError) Error() string {
	return fmt.Sprintf("ntor: Invalid Curve25519 public key length: %d",
		int(e))
}

// PrivateKeyLengthError is the error returned when the private key being
// imported is an invalid length.
type PrivateKeyLengthError int

func (e PrivateKeyLengthError) Error() string {
	return fmt.Sprintf("ntor: Invalid Curve25519 private key length: %d",
		int(e))
}

// PublicKey is a Curve25519 public key in little-endian byte order.
type PublicKey [PublicKeyLength]byte

// Bytes returns a pointer to the raw Curve25519 public key.
func (public *PublicKey) Bytes() *[PublicKeyLength]byte {
	return (*[PublicKeyLength]byte)(public)
}

// Hex returns the hexdecimal representation of the Curve25519 public key.
func (public *PublicKey) Hex() string {
	return hex.EncodeToString(public.Bytes()[:])
}

// NewPublicKey creates a PublicKey from the raw bytes.
func NewPublicKey(raw []byte) (*PublicKey, error) {
	if len(raw) != PublicKeyLength {
		return nil, PublicKeyLengthError(len(raw))
	}

	pubKey := new(PublicKey)
	copy(pubKey[:], raw)

	return pubKey, nil
}

// PublicKeyFromHex returns a PublicKey from the hexdecimal representation.
func PublicKeyFromHex(encoded string) (*PublicKey, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return NewPublicKey(raw)
}

// Representative is an Elligator representative of a Curve25519 public key
// in little-endian byte order.
type Representative [RepresentativeLength]byte

// Bytes returns a pointer to the raw Elligator representative.
func (repr *Representative) Bytes() *[RepresentativeLength]byte {
	return (*[RepresentativeLength]byte)(repr)
}

// ToPublic converts a Elligator representative to a Curve25519 public key.
func (repr *Representative) ToPublic() *PublicKey {
	pub := new(PublicKey)

	extra25519.RepresentativeToPublicKey(pub.Bytes(), repr.Bytes())
	return pub
}

// PrivateKey is a Curve25519 private key in little-endian byte order.
type PrivateKey [PrivateKeyLength]byte

// Exp sets the group element dst to be the result of x^y, over the ECDH
// group.
func Exp(dst, x, y *[GroupElementLength]byte) {
	curve25519.ScalarMult(dst, y, x)
}

// Exp calculates the shared secret with the provided public key.
func (private *PrivateKey) Exp(sharedSecret *[GroupElementLength]byte, publicKey *PublicKey) {
	p := ([GroupElementLength]byte)(*private)
	Exp(sharedSecret, (*[GroupElementLength]byte)(publicKey), &p)
}

// Bytes returns a pointer to the raw Curve25519 private key.
func (private *PrivateKey) Bytes() *[PrivateKeyLength]byte {
	return (*[PrivateKeyLength]byte)(private)
}

// Hex returns the hexdecimal representation of the Curve25519 private key.
func (private *PrivateKey) Hex() string {
	return hex.EncodeToString(private.Bytes()[:])
}

// Keypair is a Curve25519 keypair with an optional Elligator representative.
// As only certain Curve25519 keys can be obfuscated with Elligator, the
// representative must be generated along with the keypair.
type Keypair struct {
	public         *PublicKey
	private        *PrivateKey
	representative *Representative
}

// Public returns the Curve25519 public key belonging to the Keypair.
func (keypair *Keypair) Public() *PublicKey {
	return keypair.public
}

// Private returns the Curve25519 private key belonging to the Keypair.
func (keypair *Keypair) Private() *PrivateKey {
	return keypair.private
}

// Representative returns the Elligator representative of the public key
// belonging to the Keypair.
func (keypair *Keypair) Representative() *Representative {
	return keypair.representative
}

// HasElligator returns true if the Keypair has an Elligator representative.
func (keypair *Keypair) HasElligator() bool {
	return nil != keypair.representative
}

// NewKeypair generates a new Curve25519 keypair, and optionally also generates
// an Elligator representative of the public key.
func NewKeypair(elligator bool) (*Keypair, error) {
	keypair := new(Keypair)
	keypair.private = new(PrivateKey)
	keypair.public = new(PublicKey)
	if elligator {
		keypair.representative = new(Representative)
	}

	for {
		// Generate a Curve25519 private key.  Like everyone who does this,
		// run the CSPRNG output through SHA256 for extra tinfoil hattery.
		priv := keypair.private.Bytes()[:]
		_, err := rand.Reader.Read(priv)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(priv)
		digest[0] &= 248
		digest[31] &= 127
		digest[31] |= 64
		copy(priv, digest[:])

		if elligator {
			// Apply the Elligator transform.  This fails ~50% of the time.
			if !extra25519.ScalarBaseMult(keypair.public.Bytes(),
				keypair.representative.Bytes(),
				keypair.private.Bytes()) {
				continue
			}
		} else {
			// Generate the corresponding Curve25519 public key.
			curve25519.ScalarBaseMult(keypair.public.Bytes(),
				keypair.private.Bytes())
		}

		return keypair, nil
	}
}
