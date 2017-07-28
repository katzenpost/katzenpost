// ecdh.go - ECDH wrappers.
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

// Package ecdh provides ECDH (X25519) wrappers.
package ecdh

import (
	"errors"
	"io"

	"github.com/katzenpost/core/utils"
	"golang.org/x/crypto/curve25519"
)

const (
	// GroupElementLength is the length of a ECDH group element in bytes.
	GroupElementLength = 32

	// PublicKeySize is the size of a serialized PublicKey in bytes.
	PublicKeySize = GroupElementLength

	// PrivateKeySize is the size of a serialized PrivateKey in bytes.
	PrivateKeySize = GroupElementLength
)

var errInvalidKey = errors.New("sphinx: invalid key")

// PublicKey is a ECDH public key.
type PublicKey struct {
	pubBytes [GroupElementLength]byte
}

// Bytes returns the raw public key.
func (k *PublicKey) Bytes() []byte {
	return k.pubBytes[:]
}

// FromBytes deserializes the byte slice b into the PublicKey.
func (k *PublicKey) FromBytes(b []byte) error {
	if len(b) != PublicKeySize {
		return errInvalidKey
	}

	copy(k.pubBytes[:], b)

	return nil
}

// Reset clears the PublicKey structure such that no sensitive data is left
// in memory.
func (k *PublicKey) Reset() {
	utils.ExplicitBzero(k.pubBytes[:])
}

// Blind blinds the public key with the provided blinding factor.
func (k *PublicKey) Blind(blindingFactor *[GroupElementLength]byte) {
	Exp(&k.pubBytes, &k.pubBytes, blindingFactor)
}

// PrivateKey is a ECDH private key.
type PrivateKey struct {
	pubKey    PublicKey
	privBytes [GroupElementLength]byte
}

// Bytes returns the raw private key.
func (k *PrivateKey) Bytes() []byte {
	return k.privBytes[:]
}

// FromBytes deserializes the byte slice b into the PrivateKey.
func (k *PrivateKey) FromBytes(b []byte) error {
	if len(b) != PrivateKeySize {
		return errInvalidKey
	}

	copy(k.privBytes[:], b)
	expG(&k.pubKey.pubBytes, &k.privBytes)

	return nil
}

// Exp calculates the shared secret with the provided public key.
func (k *PrivateKey) Exp(sharedSecret *[GroupElementLength]byte, publicKey *PublicKey) {
	Exp(sharedSecret, &publicKey.pubBytes, &k.privBytes)
}

// Reset clears the PrivateKey structure such that no sensitive data is left
// in memory.
func (k *PrivateKey) Reset() {
	k.pubKey.Reset()
	utils.ExplicitBzero(k.privBytes[:])
}

// PublicKey returns the PublicKey corresponding to the PrivateKey.
func (k *PrivateKey) PublicKey() *PublicKey {
	return &k.pubKey
}

// NewKeypair generates a new PrivateKey sampled from the provided entropy
// source.
func NewKeypair(r io.Reader) (*PrivateKey, error) {
	k := new(PrivateKey)
	if _, err := io.ReadFull(r, k.privBytes[:]); err != nil {
		return nil, err
	}

	expG(&k.pubKey.pubBytes, &k.privBytes)

	return k, nil
}

// Exp sets the group element dst to be the result of x^y, over the ECDH
// group.
func Exp(dst, x, y *[GroupElementLength]byte) {
	curve25519.ScalarMult(dst, y, x)
}

func expG(dst, y *[GroupElementLength]byte) {
	curve25519.ScalarBaseMult(dst, y)
}
