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
	"encoding/base64"
	"io"

	ctidh "github.com/katzenpost/ctidh_cgo"

	"github.com/katzenpost/katzenpost/core/crypto/nike"
)

// CTIDH implements the Nike interface using our CTIDH module.
type Ctidh1024Nike struct{}

var CTIDH1024Scheme *Ctidh1024Nike

var _ nike.PrivateKey = (*PrivateKey)(nil)
var _ nike.PublicKey = (*PublicKey)(nil)
var _ nike.Scheme = (*Ctidh1024Nike)(nil)

func (e *Ctidh1024Nike) Name() string {
	return "ctidh"
}

// PublicKeySize returns the size in bytes of the public key.
func (e *Ctidh1024Nike) PublicKeySize() int {
	return ctidh.Ctidh1024PublicKeySize
}

// PrivateKeySize returns the size in bytes of the private key.
func (e *Ctidh1024Nike) PrivateKeySize() int {
	return ctidh.Ctidh1024PrivateKeySize
}

// NewEmptyPublicKey returns an uninitialized
// PublicKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func (e *Ctidh1024Nike) NewEmptyPublicKey() nike.PublicKey {
	return &PublicKey{
		publicKey: ctidh.NewEmptyCtidh1024PublicKey(),
	}
}

// NewEmptyPrivateKey returns an uninitialized
// PrivateKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func (e *Ctidh1024Nike) NewEmptyPrivateKey() nike.PrivateKey {
	return &PrivateKey{
		privateKey: ctidh.NewEmptyCtidh1024PrivateKey(),
	}
}

func (e *Ctidh1024Nike) GeneratePrivateKey(rng io.Reader) nike.PrivateKey {
	return &PrivateKey{
		privateKey: ctidh.GenerateCtidh1024PrivateKey(rng),
	}
}

func (e *Ctidh1024Nike) GenerateKeyPairFromEntropy(rng io.Reader) (nike.PublicKey, nike.PrivateKey, error) {
	privKey, pubKey := ctidh.GenerateCtidh1024KeyPairWithRNG(rng)
	return &PublicKey{
			publicKey: pubKey,
		}, &PrivateKey{
			privateKey: privKey,
		}, nil
}

// GenerateKeyPair creates a new key pair.
func (e *Ctidh1024Nike) GenerateKeyPair() (nike.PublicKey, nike.PrivateKey, error) {
	privKey, pubKey := ctidh.GenerateCtidh1024KeyPair()
	return &PublicKey{
			publicKey: pubKey,
		}, &PrivateKey{
			privateKey: privKey,
		}, nil
}

// DeriveSecret derives a shared secret given a private key
// from one party and a public key from another.
func (e *Ctidh1024Nike) DeriveSecret(privKey nike.PrivateKey, pubKey nike.PublicKey) []byte {
	return ctidh.DeriveSecretCtidh1024(privKey.(*PrivateKey).privateKey, pubKey.(*PublicKey).publicKey)
}

// DerivePublicKey derives a public key given a private key.
func (e *Ctidh1024Nike) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	return &PublicKey{
		publicKey: ctidh.DeriveCtidh1024PublicKey(privKey.(*PrivateKey).privateKey),
	}
}

func (e *Ctidh1024Nike) Blind(groupMember nike.PublicKey, blindingFactor nike.PrivateKey) nike.PublicKey {
	blinded, err := ctidh.BlindCtidh1024(
		blindingFactor.(*PrivateKey).privateKey,
		groupMember.(*PublicKey).publicKey,
	)
	if err != nil {
		panic(err)
	}
	return &PublicKey{
		publicKey: blinded,
	}
}

func (e *Ctidh1024Nike) UnmarshalBinaryPublicKey(b []byte) (nike.PublicKey, error) {
	pubkey := ctidh.NewEmptyCtidh1024PublicKey()
	err := pubkey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		publicKey: pubkey,
	}, nil
}

func (e *Ctidh1024Nike) UnmarshalBinaryPrivateKey(b []byte) (nike.PrivateKey, error) {
	privkey := ctidh.NewEmptyCtidh1024PrivateKey()
	err := privkey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		privateKey: privkey,
	}, nil
}

type PublicKey struct {
	publicKey *ctidh.Ctidh1024PublicKey
}

func (p *PublicKey) Blind(blindingFactor nike.PrivateKey) error {
	return p.publicKey.Blind(blindingFactor.(*PrivateKey).privateKey)
}

func (p *PublicKey) Reset() {
	p.publicKey.Reset()
}

func (p *PublicKey) Bytes() []byte {
	return p.publicKey.Bytes()
}

func (p *PublicKey) FromBytes(data []byte) error {
	return p.publicKey.FromBytes(data)
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (p *PublicKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (p *PublicKey) UnmarshalBinary(data []byte) error {
	return p.FromBytes(data)
}

// MarshalText is an implementation of a method on the
// TextMarshaler interface defined in https://golang.org/pkg/encoding/
func (p *PublicKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(p.Bytes())), nil
}

// UnmarshalText is an implementation of a method on the
// TextUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (p *PublicKey) UnmarshalText(data []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}
	return p.FromBytes(raw)
}

type PrivateKey struct {
	privateKey *ctidh.Ctidh1024PrivateKey
}

func (p *PrivateKey) Public() nike.PublicKey {
	return &PublicKey{
		publicKey: p.privateKey.Public(),
	}
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

func init() {
	CTIDH1024Scheme = &Ctidh1024Nike{}
}
