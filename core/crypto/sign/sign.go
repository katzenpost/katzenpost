// sign.go - Package sign implements signature schemes.
// Copyright (C) 2022  David Stainton.
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

// Package sign implements signature scheme interfaces
// and implementations.
package sign

import (
	"encoding"
)

// PublicKeyHashSize indicates the hash size returned
// from the PublicKey's Sum256 method.
const PublicKeyHashSize = 32

// Key is an interface for types encapsulating key material.
type Key interface {

	// KeyType is a string indicating the key type.
	KeyType() string

	// Reset resets the key material to all zeros.
	Reset()

	// Bytes serializes key material into a byte slice.
	Bytes() []byte

	// FromBytes loads key material from the given byte slice.
	FromBytes(data []byte) error

	// Identity returns the key's identity, in this case it's our
	// public key in bytes.
	Identity() []byte
}

// PrivateKey is an interface for types encapsulating
// private key material.
type PrivateKey interface {
	Key

	// Sign signs the given message and returns the signature.
	Sign(message []byte) (signature []byte)
}

// PublicKey is an interface for types encapsulating
// public key material.
type PublicKey interface {
	encoding.TextMarshaler
	encoding.TextUnmarshaler

	Key

	// Equal deterministically compares the two keys and returns true
	// if they are equal.
	Equal(PublicKey) bool

	// Verify checks whether the given signature is valid.
	Verify(signature, message []byte) bool

	// Sum256 returns the Blake2b 256-bit checksum of the key's raw bytes.
	Sum256() [32]byte
}

// Scheme is our signature scheme.
type Scheme interface {

	// NewKeypair returns a newly generated key pair.
	NewKeypair() (PrivateKey, PublicKey)

	// UnmarshalBinaryPublicKey loads a public key from byte slice.
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)

	// UnmarshalBinaryPrivateKey loads a private key from byte slice.
	UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)

	// UnmarshalTextPublicKey loads a public key from byte slice.
	UnmarshalTextPublicKey([]byte) (PublicKey, error)

	// Name of the scheme.
	Name() string

	// SignatureSize returns the size in bytes of the signature.
	SignatureSize() int

	// PublicKeySize returns the size in bytes of the public key.
	PublicKeySize() int

	// PrivateKeySize returns the size in bytes of the private key.
	PrivateKeySize() int
}
