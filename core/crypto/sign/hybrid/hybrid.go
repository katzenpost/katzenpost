// hybrid.go - Generic hybrid signature scheme.
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

package hybrid

import (
	"crypto/hmac"
	"errors"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/katzenpost/core/crypto/sign"
)

var (
	ErrPrivateKeySize = errors.New("byte slice length must match PrivateKeySize")
	ErrPublicKeySize  = errors.New("byte slice length must match PublicKeySize")
)

type scheme struct {
	scheme1 sign.Scheme
	scheme2 sign.Scheme
}

var _ sign.Scheme = (*scheme)(nil)

// NewScheme create a new hybrid signature scheme.
func NewScheme(a, b sign.Scheme) sign.Scheme {
	return &scheme{
		scheme1: a,
		scheme2: b,
	}
}

// Name of the scheme.
func (s *scheme) Name() string {
	return s.scheme1.Name() + "_" + s.scheme2.Name()
}

// NewKeypair returns a newly generated key pair.
func (s *scheme) NewKeypair() (sign.PrivateKey, sign.PublicKey) {
	privKey1, pubKey1 := s.scheme1.NewKeypair()
	privKey2, pubKey2 := s.scheme2.NewKeypair()
	return &privateKey{
			scheme:      s,
			scheme1:     s.scheme1,
			scheme2:     s.scheme2,
			privateKey1: privKey1,
			privateKey2: privKey2,
			publicKey1:  pubKey1,
			publicKey2:  pubKey2,
		}, &publicKey{
			scheme1:    s.scheme1,
			scheme2:    s.scheme2,
			publicKey1: pubKey1,
			publicKey2: pubKey2,
		}
}

// UnmarshalBinaryPublicKey loads a public key from byte slice.
func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	_, pubKey := s.NewKeypair()
	err := pubKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// UnmarshalBinaryPrivateKey loads a private key from byte slice.
func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	privKey, _ := s.NewKeypair()
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

// SignatureSize returns the size in bytes of the signature.
func (s *scheme) SignatureSize() int {
	return s.scheme1.SignatureSize() + s.scheme2.SignatureSize()
}

// PublicKeySize returns the size of a packed PublicKey
func (s *scheme) PublicKeySize() int {
	return s.scheme1.PublicKeySize() + s.scheme2.PublicKeySize()
}

// PrivateKeySize returns the size of a packed PrivateKey
func (s *scheme) PrivateKeySize() int {
	return s.scheme1.PrivateKeySize() + s.scheme2.PrivateKeySize()
}

type privateKey struct {
	scheme  sign.Scheme
	scheme1 sign.Scheme
	scheme2 sign.Scheme

	privateKey1 sign.PrivateKey
	privateKey2 sign.PrivateKey

	publicKey1 sign.PublicKey
	publicKey2 sign.PublicKey
}

func (p *privateKey) PublicKey() sign.PublicKey {
	return &publicKey{
		scheme1:    p.scheme1,
		scheme2:    p.scheme2,
		publicKey1: p.publicKey1,
		publicKey2: p.publicKey2,
	}
}

func (p *privateKey) KeyType() string {
	return p.scheme.Name()
}

func (p *privateKey) Sign(message []byte) []byte {
	return append(p.privateKey1.Sign(message),
		p.privateKey2.Sign(message)...)
}

func (p *privateKey) Reset() {}

func (p *privateKey) Identity() []byte {
	return append(p.publicKey1.Bytes(), p.publicKey2.Bytes()...)
}

func (p *privateKey) Bytes() []byte {
	return append(p.privateKey1.Bytes(), p.privateKey2.Bytes()...)
}

func (p *privateKey) FromBytes(b []byte) error {
	if len(b) != p.scheme1.PrivateKeySize()+p.scheme2.PrivateKeySize() {
		return ErrPrivateKeySize
	}
	err := p.privateKey1.FromBytes(b[:p.scheme1.PrivateKeySize()])
	if err != nil {
		return err
	}
	err = p.privateKey2.FromBytes(b[p.scheme1.PrivateKeySize():])
	if err != nil {
		return err
	}
	return nil
}

type publicKey struct {
	scheme1 sign.Scheme
	scheme2 sign.Scheme

	publicKey1 sign.PublicKey
	publicKey2 sign.PublicKey
}

func (p *publicKey) Sum256() [32]byte {
	return blake2b.Sum256(p.Bytes())
}

func (p *publicKey) Equal(pubKey sign.PublicKey) bool {
	return hmac.Equal(pubKey.Bytes(), p.Bytes())
}

func (p *publicKey) Verify(signature, message []byte) bool {
	if p.publicKey1.Verify(signature[:p.scheme1.SignatureSize()], message) == false {
		return false
	}
	if p.publicKey2.Verify(signature[p.scheme1.SignatureSize():], message) == false {
		return false
	}
	return true
}

func (p *publicKey) Reset() {
	p.publicKey1.Reset()
	p.publicKey2.Reset()
}

func (p *publicKey) Identity() []byte {
	return append(p.publicKey1.Bytes(), p.publicKey2.Bytes()...)
}

func (p *publicKey) Bytes() []byte {
	return append(p.publicKey1.Bytes(), p.publicKey2.Bytes()...)
}

func (p *publicKey) FromBytes(b []byte) error {
	err := p.publicKey1.FromBytes(b[:p.scheme1.PublicKeySize()])
	if err != nil {
		return err
	}
	err = p.publicKey2.FromBytes(b[p.scheme1.PublicKeySize():])
	if err != nil {
		return err
	}
	return nil
}
