//go:build ctidh
// +build ctidh

// ctidh.go - Adapts ctidh module to our NIKE interface.
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

package ctidh

import (
	ctidh "github.com/katzenpost/ctidh_cgo"

	"github.com/katzenpost/katzenpost/core/crypto/nike"
)

// CTIDH implements the Nike interface using our CTIDH module.
type CtidhNike struct {
}

var CTIDHScheme = &CtidhNike{}

var _ nike.PrivateKey = (*ctidh.PrivateKey)(nil)
var _ nike.PublicKey = (*ctidh.PublicKey)(nil)
var _ nike.Scheme = (*CtidhNike)(nil)

// PublicKeySize returns the size in bytes of the public key.
func (e *CtidhNike) PublicKeySize() int {
	return ctidh.PublicKeySize
}

// PrivateKeySize returns the size in bytes of the private key.
func (e *CtidhNike) PrivateKeySize() int {
	return ctidh.PrivateKeySize
}

// NewEmptyPublicKey returns an uninitialized
// PublicKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func (e *CtidhNike) NewEmptyPublicKey() nike.PublicKey {
	return ctidh.NewEmptyPublicKey()
}

// NewEmptyPrivateKey returns an uninitialized
// PrivateKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func (e *CtidhNike) NewEmptyPrivateKey() nike.PrivateKey {
	return ctidh.NewEmptyPrivateKey()
}

// NewKeypair returns a newly generated key pair.
func (e *CtidhNike) NewKeypair() (nike.PrivateKey, nike.PublicKey) {
	privKey, pubKey := ctidh.GenerateKeyPair()
	return privKey, pubKey
}

// DeriveSecret derives a shared secret given a private key
// from one party and a public key from another.
func (e *CtidhNike) DeriveSecret(privKey nike.PrivateKey, pubKey nike.PublicKey) []byte {
	return ctidh.DeriveSecret(privKey.(*ctidh.PrivateKey), pubKey.(*ctidh.PublicKey))
}

// DerivePublicKey derives a public key given a private key.
func (e *CtidhNike) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	return ctidh.DerivePublicKey(privKey.(*ctidh.PrivateKey))
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
func (e *CtidhNike) Blind(groupMember []byte, blindingFactor []byte) []byte {
	pubkey := ctidh.NewEmptyPublicKey()
	err := pubkey.FromBytes(groupMember)
	if err != nil {
		panic(err)
	}
	blinded, err := ctidh.Blind(blindingFactor, pubkey)
	if err != nil {
		panic(err)
	}
	return blinded.Bytes()
}

func (e *CtidhNike) UnmarshalBinaryPublicKey(b []byte) (nike.PublicKey, error) {
	pubkey := ctidh.NewEmptyPublicKey()
	err := pubkey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubkey, nil
}
