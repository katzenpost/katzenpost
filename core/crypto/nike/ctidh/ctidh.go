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
	"io"

	ctidh "github.com/katzenpost/ctidh_cgo"

	"github.com/katzenpost/katzenpost/core/crypto/nike"
)

// CTIDH implements the Nike interface using our CTIDH module.
type CtidhNike struct {
}

var CTIDHScheme = &CtidhNike{}

var _ nike.PrivateKey = (*PrivateKey)(nil)
var _ nike.PublicKey = (*ctidh.PublicKey)(nil)
var _ nike.Scheme = (*CtidhNike)(nil)

func (e *CtidhNike) Name() string {
	return "ctidh"
}

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
	return &PrivateKey{
		privateKey: ctidh.NewEmptyPrivateKey(),
	}
}

func (e *CtidhNike) GenerateKeyPairFromEntropy(rng io.Reader) (nike.PublicKey, nike.PrivateKey, error) {
	privKey, pubKey := ctidh.GenerateKeyPairWithRNG(rng)
	return pubKey, &PrivateKey{
		privateKey: privKey,
	}, nil
}

// GenerateKeyPair creates a new key pair.
func (e *CtidhNike) GenerateKeyPair() (nike.PublicKey, nike.PrivateKey, error) {
	privKey, pubKey := ctidh.GenerateKeyPair()
	return pubKey, &PrivateKey{
		privateKey: privKey,
	}, nil
}

// DeriveSecret derives a shared secret given a private key
// from one party and a public key from another.
func (e *CtidhNike) DeriveSecret(privKey nike.PrivateKey, pubKey nike.PublicKey) []byte {
	return ctidh.DeriveSecret(privKey.(*PrivateKey).privateKey, pubKey.(*ctidh.PublicKey))
}

// DerivePublicKey derives a public key given a private key.
func (e *CtidhNike) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	return ctidh.DerivePublicKey(privKey.(*PrivateKey).privateKey)
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

func (e *CtidhNike) UnmarshalBinaryPrivateKey(b []byte) (nike.PrivateKey, error) {
	privkey := ctidh.NewEmptyPrivateKey()
	err := privkey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		privateKey: privkey,
	}, nil
}

type PrivateKey struct {
	privateKey *ctidh.PrivateKey
}

func (p *PrivateKey) Public() nike.PublicKey {
	return p.privateKey.Public()
}

func (p *PrivateKey) Reset() {
	p.privateKey.Reset()
}

func (p *PrivateKey) Bytes() []byte {
	return p.privateKey.Bytes()
}

func (p *PrivateKey) FromBytes(data []byte) error {
	return p.privateKey.FromBytes(data)
}

func (p *PrivateKey) MarshalBinary() ([]byte, error) {
	return p.privateKey.MarshalBinary()
}

func (p *PrivateKey) MarshalText() ([]byte, error) {
	return p.privateKey.MarshalText()
}

func (p *PrivateKey) UnmarshalBinary(data []byte) error {
	return p.privateKey.UnmarshalBinary(data)
}

func (p *PrivateKey) UnmarshalText(data []byte) error {
	return p.privateKey.UnmarshalText(data)
}
