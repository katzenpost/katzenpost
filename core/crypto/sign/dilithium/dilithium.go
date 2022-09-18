// dilithium.go - Implements interface wrapper around dilithium2-AES from NIST round 3
// as an implementation of our signature scheme interfaces.
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

// Package dilithium implements dilithium2-AES from NIST round 3
// as an implementation of our signature scheme interfaces.
package dilithium

import (
	"errors"

	"github.com/cloudflare/circl/sign/dilithium"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
)

var (
	ErrPrivateKeySize = errors.New("byte slice length must match PrivateKeySize")
	ErrPublicKeySize  = errors.New("byte slice length must match PublicKeySize")
)

var Scheme = &scheme{
	mode: dilithium.Mode2AES,
}

type scheme struct {
	mode dilithium.Mode
}

var _ sign.Scheme = (*scheme)(nil)

// Name of the scheme.
func (s *scheme) Name() string {
	return "Dilithium2AES"
}

// NewKeypair returns a newly generated key pair.
func (s *scheme) NewKeypair() (sign.PrivateKey, sign.PublicKey) {
	pubKey, privKey, err := s.mode.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &privateKey{
			scheme:     s,
			privateKey: privKey,
		}, &publicKey{
			scheme:    s,
			publicKey: pubKey,
		}
}

// UnmarshalBinaryPublicKey loads a public key from byte slice.
func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	if len(b) != s.PublicKeySize() {
		return nil, ErrPublicKeySize
	}
	pubKey := &publicKey{
		scheme:    s,
		publicKey: s.mode.PublicKeyFromBytes(b),
	}
	return pubKey, nil
}

// UnmarshalBinaryPrivateKey loads a private key from byte slice.
func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	if len(b) != s.PrivateKeySize() {
		return nil, ErrPrivateKeySize
	}
	privKey := &privateKey{
		scheme:     s,
		privateKey: s.mode.PrivateKeyFromBytes(b),
	}
	return privKey, nil
}

// SignatureSize returns the size in bytes of the signature.
func (s *scheme) SignatureSize() int {
	return s.mode.SignatureSize()
}

// PublicKeySize returns the size of a packed PublicKey
func (s *scheme) PublicKeySize() int {
	return s.mode.PublicKeySize()
}

// PrivateKeySize returns the size of a packed PrivateKey
func (s *scheme) PrivateKeySize() int {
	return s.mode.PrivateKeySize()
}

type privateKey struct {
	scheme     *scheme
	privateKey dilithium.PrivateKey
	publicKey  *publicKey
}

func (p *privateKey) Sign(message []byte) []byte {
	return p.scheme.mode.Sign(p.privateKey, message)
}

func (p *privateKey) Reset() {
	// XXX FIXME
	p.privateKey = nil
}

func (p *privateKey) Bytes() []byte {
	return p.privateKey.Bytes()
}

func (p *privateKey) FromBytes(b []byte) error {
	if len(b) != p.scheme.PrivateKeySize() {
		return ErrPrivateKeySize
	}
	p.privateKey = p.scheme.mode.PrivateKeyFromBytes(b)
	return nil
}

type publicKey struct {
	scheme    *scheme
	publicKey dilithium.PublicKey
}

func (p *publicKey) Verify(message, signature []byte) bool {
	return p.scheme.mode.Verify(p.publicKey, message, signature)
}

func (p *publicKey) Reset() {
	// XXX FIXME
	p.publicKey = nil
}

func (p *publicKey) Bytes() []byte {
	return p.publicKey.Bytes()
}

func (p *publicKey) FromBytes(b []byte) error {
	if len(b) != p.scheme.PublicKeySize() {
		return ErrPublicKeySize
	}
	p.publicKey = p.scheme.mode.PublicKeyFromBytes(b)
	return nil
}
