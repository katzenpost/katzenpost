// ecdh.go - Sphinx Packet Format ECDH wrappers.
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

package sphinx

import (
	"errors"
	"io"

	"github.com/katzenpost/core/sphinx/internal/crypto"
	"github.com/katzenpost/core/utils"
)

const (
	// PublicKeySize is the size of a serialized PublicKey in bytes.
	PublicKeySize = crypto.GroupElementLength

	// PrivateKeySize is the size of a serialized PrivateKey in bytes.
	PrivateKeySize = crypto.GroupElementLength
)

var errInvalidKey = errors.New("sphinx: invalid key")

// PublicKey is a Sphinx Packet Format public key.
type PublicKey struct {
	pubBytes [crypto.GroupElementLength]byte
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

func (k *PublicKey) blind(blindingFactor *[crypto.GroupElementLength]byte) {
	crypto.Exp(&k.pubBytes, &k.pubBytes, blindingFactor)
}

// PrivateKey is a Sphinx Packet Format private key.
type PrivateKey struct {
	pubKey    PublicKey
	privBytes [crypto.GroupElementLength]byte
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
	crypto.ExpG(&k.pubKey.pubBytes, &k.privBytes)

	return nil
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

	if err := crypto.ExpKeygen(&k.privBytes, r); err != nil {
		return nil, err
	}
	crypto.ExpG(&k.pubKey.pubBytes, &k.privBytes)

	return k, nil
}
