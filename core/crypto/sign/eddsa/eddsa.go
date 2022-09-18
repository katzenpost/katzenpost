// eddsa.go - Implements interface wrapper around ed25519 wrapper.
//
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

// Package eddsa implements interface wrapper around ed25519 wrapper.
package eddsa

import (
	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
)

// Scheme implements our sign.Scheme interface using the ed25519 wrapper.
var Scheme = &scheme{}

type scheme struct{}

var _ sign.Scheme = (*scheme)(nil)

// NewKeypair returns a newly generated key pair.
func (s *scheme) NewKeypair() (sign.PrivateKey, sign.PublicKey) {
	privKey, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}
	return privKey, privKey.PublicKey()
}

// UnmarshalBinaryPublicKey loads a public key from byte slice.
func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	pubKey := new(eddsa.PublicKey)
	err := pubKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// UnmarshalBinaryPrivateKey loads a private key from byte slice.
func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	privKey := new(eddsa.PrivateKey)
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

// SignatureSize returns the size in bytes of the signature.
func (s *scheme) SignatureSize() int {
	return eddsa.SignatureSize
}

// PublicKeySize returns the size of a packed PublicKey
func (s *scheme) PublicKeySize() int {
	return eddsa.PublicKeySize
}

// PrivateKeySize returns the size of a packed PrivateKey
func (s *scheme) PrivateKeySize() int {
	return eddsa.PrivateKeySize
}
