// nike.go - NIKE interface for non-interactive key exchange.
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

// Package sphinx implements the Katzenpost parameterized Sphinx Packet Format.
package nike

import (
	"encoding"
	"io"
)

// Key is an interface for types encapsulating key material.
type Key interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	encoding.TextMarshaler
	encoding.TextUnmarshaler

	// Reset resets the key material to all zeros.
	Reset()

	// Bytes serializes key material into a byte slice.
	Bytes() []byte

	// FromBytes loads key material from the given byte slice.
	FromBytes(data []byte) error
}

// PrivateKey is an interface for types encapsulating
// private key material.
type PrivateKey interface {
	Key

	Public() PublicKey
}

// PublicKey is an interface for types encapsulating
// public key material.
type PublicKey interface {
	Key

	// Blind performs a blinding operation and mutates the public
	// key with the blinded value.
	Blind(blindingFactor PrivateKey) error
}

// Scheme is an interface encapsulating a
// non-interactive key exchange.
type Scheme interface {

	// Name returns the name of the NIKE scheme implementation.
	Name() string

	// PublicKeySize returns the size in bytes of the public key.
	PublicKeySize() int

	// PrivateKeySize returns the size in bytes of the private key.
	PrivateKeySize() int

	// GeneratePrivateKey uses the given RNG to derive a new private key.
	// This can be used to deterministically generate private keys if the
	// entropy source is deterministic, for example an HKDF.
	GeneratePrivateKey(rng io.Reader) PrivateKey

	// GenerateKeyPair creates a new key pair.
	GenerateKeyPair() (PublicKey, PrivateKey, error)

	// GenerateKeyPairFromEntropy creates a new key pair from the given entropy source.
	GenerateKeyPairFromEntropy(rng io.Reader) (PublicKey, PrivateKey, error)

	// DeriveSecret derives a shared secret given a private key
	// from one party and a public key from another.
	DeriveSecret(PrivateKey, PublicKey) []byte

	// DerivePublicKey derives a public key given a private key.
	DerivePublicKey(PrivateKey) PublicKey

	// Blind performs the blinding operation against the
	// given group member, returning the blinded key.
	Blind(groupMember PublicKey, blindingFactor PrivateKey) (blindedGroupMember PublicKey)

	// NewEmptyPublicKey returns an uninitialized
	// PublicKey which is suitable to be loaded
	// via some serialization format via FromBytes
	// or FromPEMFile methods.
	NewEmptyPublicKey() PublicKey

	// NewEmptyPrivateKey returns an uninitialized
	// PrivateKey which is suitable to be loaded
	// via some serialization format via FromBytes
	// or FromPEMFile methods.
	NewEmptyPrivateKey() PrivateKey

	// UnmarshalBinaryPublicKey loads a public key from byte slice.
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)

	// Unmarshals a PrivateKey from the provided buffer.
	UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)
}
