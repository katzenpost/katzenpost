// crypto.go - Cryptographic primitive wrappers.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package crypto provides the Katzenpost parameterization of the Sphinx Packet
// Format cryptographic operations.
package crypto

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"git.schwanenlied.me/yawning/aez.git"
	"git.schwanenlied.me/yawning/bsaes.git"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/utils"
)

const (
	// HashLength is the output size of the unkeyed hash in bytes.
	HashLength = sha512.Size256

	// MACKeyLength is the key size of the MAC in bytes.
	MACKeyLength = 32

	// MACLength is the tag size of the MAC in bytes.
	MACLength = 16

	// StreamKeyLength is the key size of the stream cipher in bytes.
	StreamKeyLength = 16

	// StreamIVLength is the IV size of the stream cipher in bytes.
	StreamIVLength = 16

	// SPRPKeyLength is the key size of the SPRP in bytes.
	SPRPKeyLength = 48

	// SPRPIVLength is the IV size of the SPRP in bytes.
	SPRPIVLength = StreamIVLength

	// GroupElementLength is the length of a DH group element in bytes.
	GroupElementLength = ecdh.GroupElementLength

	okmLength = MACKeyLength + StreamKeyLength + StreamIVLength + SPRPKeyLength + GroupElementLength
	kdfInfo   = "katzenpost-kdf-v0-hkdf-sha256"
)

type resetable interface {
	Reset()
}

type macWrapper struct {
	hash.Hash
}

func (m *macWrapper) Sum(b []byte) []byte {
	tmp := m.Hash.Sum(nil)
	b = append(b, tmp[0:MACLength]...)
	return b
}

// Stream is the Sphinx stream cipher.
type Stream struct {
	cipher.Stream
}

// KeyStream fills the buffer dst with key stream output.
func (s *Stream) KeyStream(dst []byte) {
	// TODO: Add a fast path for implementations that support it, to
	// shave off the memset and XOR.
	utils.ExplicitBzero(dst)
	s.XORKeyStream(dst, dst)
}

// Reset clears the Stream instance such that no sensitive data is left in
// memory.
func (s *Stream) Reset() {
	// bsaes's ctrAble implementation exposes this, `crypto/aes` does not,
	// c'est la vie.
	if r, ok := s.Stream.(resetable); ok {
		r.Reset()
	}
}

// Hash calculates the digest of message m.
func Hash(msg []byte) [HashLength]byte {
	return sha512.Sum512_256(msg)
}

// NewMAC returns a new hash.Hash implementing the Sphinx MAC with the provided
// key.
func NewMAC(key *[MACKeyLength]byte) hash.Hash {
	return &macWrapper{hmac.New(sha256.New, key[:])}
}

// NewStream returns a new Stream implementing the Sphinx Stream Cipher with
// the provided key and IV.
func NewStream(key *[StreamKeyLength]byte, iv *[StreamIVLength]byte) *Stream {
	// bsaes is smart enough to detect if the Go runtime and the CPU support
	// AES-NI and PCLMULQDQ and call `crypto/aes`.
	//
	// TODO: The AES-NI `crypto/aes` CTR mode implementation is horrid and
	// massively underperforms so eventually bsaes should include assembly.
	blk, err := bsaes.NewCipher(key[:])
	if err != nil {
		// Not covered by unit tests because this indicates a bug in bsaes.
		panic("crypto/NewStream: failed to create AES instance: " + err.Error())
	}
	return &Stream{cipher.NewCTR(blk, iv[:])}
}

// SPRPEncrypt returns the ciphertext of the message msg, encrypted via the
// Sphinx SPRP with the provided key and IV.
func SPRPEncrypt(key *[SPRPKeyLength]byte, iv *[SPRPIVLength]byte, msg []byte) []byte {
	return aez.Encrypt(key[:], iv[:], nil, 0, msg, nil)
}

// SPRPDecrypt returns the plaintext of the message msg, decrypted via the
// Sphinx SPRP with the provided key and IV.
func SPRPDecrypt(key *[SPRPKeyLength]byte, iv *[SPRPIVLength]byte, msg []byte) []byte {
	dst, ok := aez.Decrypt(key[:], iv[:], nil, 0, msg, nil)
	if !ok {
		// Not covered by unit tests because this indicates a bug in the AEZ
		// implementation, that is hard to force.
		panic("crypto/SPRPDecrypt: BUG - aez.Decrypt failed with tau = 0")
	}
	return dst
}

// PacketKeys are the per-hop Sphinx Packet Keys, derived from the blinded
// DH key exchange.
type PacketKeys struct {
	HeaderMAC          [MACKeyLength]byte
	HeaderEncryption   [StreamKeyLength]byte
	HeaderEncryptionIV [StreamIVLength]byte
	PayloadEncryption  [SPRPKeyLength]byte
	BlindingFactor     [GroupElementLength]byte
}

// Reset clears the PacketKeys structure such that no sensitive data is left
// in memory.
func (k *PacketKeys) Reset() {
	utils.ExplicitBzero(k.HeaderMAC[:])
	utils.ExplicitBzero(k.HeaderEncryption[:])
	utils.ExplicitBzero(k.HeaderEncryptionIV[:])
	utils.ExplicitBzero(k.PayloadEncryption[:])
	utils.ExplicitBzero(k.BlindingFactor[:])
}

// KDF takes the input key material and returns the Sphinx Packet keys.
func KDF(ikm *[GroupElementLength]byte) *PacketKeys {
	okm := hkdfExpand(sha256.New, ikm[:], []byte(kdfInfo), okmLength)
	defer utils.ExplicitBzero(okm)
	ptr := okm

	k := new(PacketKeys)
	copy(k.HeaderMAC[:], ptr[:MACKeyLength])
	ptr = ptr[MACKeyLength:]
	copy(k.HeaderEncryption[:], ptr[:StreamKeyLength])
	ptr = ptr[StreamKeyLength:]
	copy(k.HeaderEncryptionIV[:], ptr[:StreamIVLength])
	ptr = ptr[StreamIVLength:]
	copy(k.PayloadEncryption[:], ptr[:SPRPKeyLength])
	ptr = ptr[SPRPKeyLength:]
	copy(k.BlindingFactor[:], ptr[:GroupElementLength])

	return k
}
