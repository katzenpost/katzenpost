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

// Key is an interface for types encapsulating key material.
type Key interface {

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
}

// PublicKey is an interface for types encapsulating
// public key material.
type PublicKey interface {
	Key

	// Blind performs a blinding operation and mutates the public
	// key with the blinded value.
	Blind(blindingFactor []byte) error
}

// Nike is an interface encapsulating a
// non-interactive key exchange.
type Nike interface {

	// PublicKeySize returns the size in bytes of the public key.
	PublicKeySize() int

	// PrivateKeySize returns the size in bytes of the private key.
	PrivateKeySize() int

	// NewKeypair returns a newly generated key pair.
	NewKeypair() (PrivateKey, PublicKey)

	// DeriveSecret derives a shared secret given a private key
	// from one party and a public key from another.
	DeriveSecret(PrivateKey, PublicKey) []byte

	// DerivePublicKey derives a public key given a private key.
	DerivePublicKey(PrivateKey) PublicKey

	// Blind performs the blinding operation against the
	// two byte slices and returns the blinded value.
	//
	// Note that the two arguments must be the correct lengths:
	//
	// * groupMember must be the size of a public key.
	//
	// * blindingFactor must be the size of a private key.
	//
	// See also PublicKey's Blind method.
	Blind(groupMember []byte, blindingFactor []byte) (blindedGroupMember []byte, err error)
}
