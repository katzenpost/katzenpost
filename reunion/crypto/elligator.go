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

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/core/utils"
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

// RepresentativeKeyLengthError is the error returned when the public key being
// imported is an invalid length.
type RepresentativeKeyLengthError int

func (e RepresentativeKeyLengthError) Error() string {
	return fmt.Sprintf("ntor: Invalid Elligator Representative Curve25519 public key length: %d",
		int(e))
}

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
func (k *PublicKey) Bytes() *[PublicKeyLength]byte {
	return (*[PublicKeyLength]byte)(k)
}

// FromBytes deserializes the byte slice b into the PublicKey.
func (k *PublicKey) FromBytes(b []byte) error {
	if len(b) != PublicKeyLength {
		return PublicKeyLengthError(len(b))
	}
	copy((*[PublicKeyLength]byte)(k)[:], b)
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (k *PublicKey) MarshalBinary() ([]byte, error) {
	return k.Bytes()[:], nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (k *PublicKey) UnmarshalBinary(data []byte) error {
	return k.FromBytes(data)
}

// Hex returns the hexdecimal representation of the Curve25519 public key.
func (k *PublicKey) Hex() string {
	return hex.EncodeToString(k.Bytes()[:])
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

// FromBytes deserializes the byte slice b into the PublicKey.
func (repr *Representative) FromBytes(b []byte) error {
	if len(b) != RepresentativeLength {
		return RepresentativeKeyLengthError(len(b))
	}
	copy((*[RepresentativeLength]byte)(repr)[:], b)
	return nil
}

// Bytes returns a pointer to the raw Elligator representative.
func (repr *Representative) Bytes() *[RepresentativeLength]byte {
	return (*[RepresentativeLength]byte)(repr)
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (repr *Representative) MarshalBinary() ([]byte, error) {
	return repr.Bytes()[:], nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (repr *Representative) UnmarshalBinary(data []byte) error {
	return repr.FromBytes(data)
}

// ToPublic converts a Elligator representative to a Curve25519 public key.
func (repr *Representative) ToPublic() *PublicKey {
	pub := new(PublicKey)

	// to be replaced with elligator2:
	// extra25519.RepresentativeToPublicKey(pub.Bytes(), repr.Bytes())
	return pub
}

// PrivateKey is a Curve25519 private key in little-endian byte order.
type PrivateKey struct {
	privBuf *[32]byte
}

// NewEmptyPrivateKey creates a new PrivateKey with the lockedBuffer
// initialized to the correct size but not yet initialized to random
// bytes.
func NewEmptyPrivateKey() *PrivateKey {
	pkb := &[32]byte{}
	_, err := rand.Reader.Read(pkb[:])
	if err != nil {
		panic(err)
	}
	p := &PrivateKey{
		privBuf: pkb,
	}
	return p
}

// NewRandomPrivateKey creates a new PrivateKey with the lockedBuffer
// initialized to PrivateKeyLength random bytes.
func NewRandomPrivateKey() *PrivateKey {
	pkb := &[32]byte{}
	_, err := rand.Reader.Read(pkb[:])
	if err != nil {
		panic(err)
	}
	p := &PrivateKey{
		privBuf: pkb,
	}
	r := p.privBuf[:]
	digest := sha256.Sum256(r)
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64
	copy(r, digest[:])
	return p
}

// Exp sets the group element dst to be the result of x^y, over the ECDH
// group.
func Exp(dst, x, y *[GroupElementLength]byte) {
	curve25519.ScalarMult(dst, y, x)
}

// Exp calculates the shared secret with the provided public key.
func (k *PrivateKey) Exp(sharedSecret *[GroupElementLength]byte, publicKey *PublicKey) {
	Exp(sharedSecret, (*[GroupElementLength]byte)(publicKey), k.ByteArray32())
}

// FromBytes deserializes the byte slice b into the PrivateKey.
func (k *PrivateKey) FromBytes(b []byte) error {
	if len(b) != PrivateKeyLength {
		return PrivateKeyLengthError(len(b))
	}
	copy(k.privBuf[:], b)
	return nil
}

// Destroy destroys the private key material and frees up the memory.
func (k *PrivateKey) Destroy() {
	utils.ExplicitBzero(k.privBuf[:])
}

// Bytes returns a pointer to the raw Curve25519 private key.
func (k *PrivateKey) Bytes() []byte {
	return k.privBuf[:]
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (k *PrivateKey) MarshalBinary() ([]byte, error) {
	return k.Bytes(), nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (k *PrivateKey) UnmarshalBinary(data []byte) error {
	return k.FromBytes(data)
}

// ByteArray32 returns a pointer to the raw Curve25519 private key.
func (k *PrivateKey) ByteArray32() *[32]byte {
	return k.privBuf
}

// Hex returns the hexdecimal representation of the Curve25519 private key.
func (k *PrivateKey) Hex() string {
	return hex.EncodeToString(k.Bytes()[:])
}

// KeypairSerializable is used to help serialize Keypair.
type KeypairSerializable struct {
	Public         *PublicKey
	Private        *PrivateKey
	Representative *Representative
}

// Keypair is a Curve25519 keypair with an optional Elligator representative.
// As only certain Curve25519 keys can be obfuscated with Elligator, the
// representative must be generated along with the keypair.
type Keypair struct {
	public         *PublicKey
	private        *PrivateKey
	representative *Representative
}

// Destroy causes the private key meterial to be destroyed.
func (keypair *Keypair) Destroy() {
	keypair.private.Destroy()
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

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (keypair *Keypair) MarshalBinary() ([]byte, error) {
	k := KeypairSerializable{
		Public:         keypair.public,
		Private:        keypair.private,
		Representative: keypair.representative,
	}
	return cbor.Marshal(k)
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (keypair *Keypair) UnmarshalBinary(data []byte) error {
	k := &KeypairSerializable{
		Public: &PublicKey{},
		Private: &PrivateKey{
			privBuf: &[PrivateKeyLength]byte{},
		},
		Representative: &Representative{},
	}
	err := cbor.Unmarshal(data, k)
	if err != nil {
		return err
	}
	keypair.public = k.Public
	keypair.private = k.Private
	keypair.representative = k.Representative
	return nil
}

// NewKeypair generates a new Curve25519 keypair, and optionally also generates
// an Elligator representative of the public key.
func NewKeypair(elligator bool) (*Keypair, error) {
	keypair := new(Keypair)
	keypair.public = new(PublicKey)
	if elligator {
		keypair.representative = new(Representative)
	}

	for {
		keypair.private = NewRandomPrivateKey()
		if elligator {
			// Apply the Elligator transform.  This fails ~50% of the time.
			//if !extra25519.ScalarBaseMult(keypair.public.Bytes(),
			//	keypair.representative.Bytes(),
			//	keypair.private.ByteArray32()) {
			//	continue
			//}
		} else {
			// Generate the corresponding Curve25519 public key.
			curve25519.ScalarBaseMult(keypair.public.Bytes(),
				keypair.private.ByteArray32())
		}

		return keypair, nil
	}
}
