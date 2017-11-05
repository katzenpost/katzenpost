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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"

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

var errInvalidKey = errors.New("ecdh: invalid key")

// PublicKey is a ECDH public key.
type PublicKey struct {
	pubBytes  [GroupElementLength]byte
	hexString string
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
	k.rebuildHexString()

	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (k *PublicKey) MarshalBinary() ([]byte, error) {
	return k.Bytes(), nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (k *PublicKey) UnmarshalBinary(data []byte) error {
	return k.FromBytes(data)
}

// MarshalText is an implementation of a method on the
// TextMarshaler interface defined in https://golang.org/pkg/encoding/
func (k *PublicKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(k.Bytes())), nil
}

// UnmarshalText is an implementation of a method on the
// TextUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (k *PublicKey) UnmarshalText(data []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}
	return k.FromBytes(raw)
}

// Reset clears the PublicKey structure such that no sensitive data is left
// in memory.
func (k *PublicKey) Reset() {
	utils.ExplicitBzero(k.pubBytes[:])
	k.hexString = "[scrubbed]"
}

// Blind blinds the public key with the provided blinding factor.
func (k *PublicKey) Blind(blindingFactor *[GroupElementLength]byte) {
	Exp(&k.pubBytes, &k.pubBytes, blindingFactor)
}

// String returns the public key as a hexdecimal encoded string.
func (k *PublicKey) String() string {
	return k.hexString
}

func (k *PublicKey) rebuildHexString() {
	k.hexString = strings.ToUpper(hex.EncodeToString(k.pubBytes[:]))
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
	k.pubKey.rebuildHexString()

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
	k.pubKey.rebuildHexString()

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
