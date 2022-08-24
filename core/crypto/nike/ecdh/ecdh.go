// ecdh.go - Adapts ecdh module to our NIKE interface.
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

package ecdh

import (
	"errors"
	"io"

	"github.com/katzenpost/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/nike"
)

var (
	// ErrBlindDataSizeInvalid indicates that the blinding data size was invalid.
	ErrBlindDataSizeInvalid error = errors.New("ecdh/nike: blinding data size invalid")
)

// EcdhNike implements the Nike interface using our ecdh module.
type EcdhNike struct {
	rng io.Reader
}

// NewEcdhNike instantiates a new EcdhNike given a CSPRNG.
func NewEcdhNike(rng io.Reader) *EcdhNike {
	return &EcdhNike{
		rng: rng,
	}
}

var _ nike.PrivateKey = (*ecdh.PrivateKey)(nil)
var _ nike.PublicKey = (*ecdh.PublicKey)(nil)
var _ nike.Nike = (*EcdhNike)(nil)

// PublicKeySize returns the size in bytes of the public key.
func (e *EcdhNike) PublicKeySize() int {
	return ecdh.PublicKeySize
}

// PrivateKeySize returns the size in bytes of the private key.
func (e *EcdhNike) PrivateKeySize() int {
	return ecdh.PublicKeySize
}

// NewKeypair returns a newly generated key pair.
func (e *EcdhNike) NewKeypair() (nike.PrivateKey, nike.PublicKey) {
	privKey, err := ecdh.NewKeypair(e.rng)
	if err != nil {
		panic(err)
	}
	return privKey, privKey.PublicKey()
}

// DeriveSecret derives a shared secret given a private key
// from one party and a public key from another.
func (e *EcdhNike) DeriveSecret(privKey nike.PrivateKey, pubKey nike.PublicKey) []byte {
	sharedSecret := privKey.(*ecdh.PrivateKey).Exp(pubKey.(*ecdh.PublicKey))
	return sharedSecret[:]
}

// DerivePublicKey derives a public key given a private key.
func (e *EcdhNike) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	return privKey.(*ecdh.PrivateKey).PublicKey()
}

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
func (e *EcdhNike) Blind(groupMember []byte, blindingFactor []byte) (blindedGroupMember []byte, err error) {
	if len(groupMember) != ecdh.PublicKeySize {
		return nil, ErrBlindDataSizeInvalid
	}
	if len(blindingFactor) != ecdh.PrivateKeySize {
		return nil, ErrBlindDataSizeInvalid
	}
	sharedSecret := ecdh.Exp(groupMember, blindingFactor)
	return sharedSecret, nil
}
