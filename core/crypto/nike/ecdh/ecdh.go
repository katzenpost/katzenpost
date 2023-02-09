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
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var (
	// ErrBlindDataSizeInvalid indicates that the blinding data size was invalid.
	ErrBlindDataSizeInvalid error = errors.New("ecdh/nike: blinding data size invalid")
)

var _ nike.PrivateKey = (*PrivateKey)(nil)
var _ nike.PublicKey = (*ecdh.PublicKey)(nil)
var _ nike.Scheme = (*EcdhNike)(nil)

var EcdhScheme nike.Scheme

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

type PrivateKey struct {
	privateKey *ecdh.PrivateKey
}

func (p *PrivateKey) Public() nike.PublicKey {
	return p.privateKey.PublicKey()
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

func (e *EcdhNike) GenerateKeyPair() (nike.PublicKey, nike.PrivateKey, error) {
	privKey, err := ecdh.NewKeypair(e.rng)
	if err != nil {
		return nil, nil, err
	}
	p := &PrivateKey{
		privateKey: privKey,
	}
	return p.Public(), p, nil
}

func (e *EcdhNike) Name() string {
	return "x25519"
}

// PublicKeySize returns the size in bytes of the public key.
func (e *EcdhNike) PublicKeySize() int {
	return ecdh.PublicKeySize
}

// PrivateKeySize returns the size in bytes of the private key.
func (e *EcdhNike) PrivateKeySize() int {
	return ecdh.PublicKeySize
}

// NewEmptyPublicKey returns an uninitialized
// PublicKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func (e *EcdhNike) NewEmptyPublicKey() nike.PublicKey {
	return new(ecdh.PublicKey)
}

// NewEmptyPrivateKey returns an uninitialized
// PrivateKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func (e *EcdhNike) NewEmptyPrivateKey() nike.PrivateKey {
	return &PrivateKey{
		privateKey: new(ecdh.PrivateKey),
	}
}

// DeriveSecret derives a shared secret given a private key
// from one party and a public key from another.
func (e *EcdhNike) DeriveSecret(privKey nike.PrivateKey, pubKey nike.PublicKey) []byte {
	sharedSecret := privKey.(*PrivateKey).privateKey.Exp(pubKey.(*ecdh.PublicKey))
	return sharedSecret[:]
}

// DerivePublicKey derives a public key given a private key.
func (e *EcdhNike) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	return privKey.(*PrivateKey).privateKey.PublicKey()
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
func (e *EcdhNike) Blind(groupMember []byte, blindingFactor []byte) []byte {
	if len(groupMember) != ecdh.PublicKeySize {
		panic(ErrBlindDataSizeInvalid)
	}
	if len(blindingFactor) != ecdh.PrivateKeySize {
		panic(ErrBlindDataSizeInvalid)
	}
	sharedSecret := ecdh.Exp(groupMember, blindingFactor)
	return sharedSecret
}

// UnmarshalBinaryPublicKey loads a public key from byte slice.
func (e *EcdhNike) UnmarshalBinaryPublicKey(b []byte) (nike.PublicKey, error) {
	pubKey := new(ecdh.PublicKey)
	err := pubKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubKey, err
}

// UnmarshalBinaryPrivateKey loads a private key from byte slice.
func (e *EcdhNike) UnmarshalBinaryPrivateKey(b []byte) (nike.PrivateKey, error) {
	privKey := &PrivateKey{
		privateKey: new(ecdh.PrivateKey),
	}
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, err
}

func init() {
	EcdhScheme = NewEcdhNike(rand.Reader)
}
