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
	"crypto/hmac"
	"encoding/base64"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
)

// Scheme implements our sign.Scheme interface using the ed25519 wrapper.
var Scheme = &scheme{}

type scheme struct{}

var _ sign.Scheme = (*scheme)(nil)

func (s *scheme) NewKeypair() (sign.PrivateKey, sign.PublicKey) {
	privKey, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &privateKey{
			privateKey: privKey,
		}, &publicKey{
			publicKey: privKey.PublicKey(),
		}
}

func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	pubKey := new(eddsa.PublicKey)
	err := pubKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &publicKey{
		publicKey: pubKey,
	}, nil
}

func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	privKey := new(eddsa.PrivateKey)
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return &privateKey{
		privateKey: privKey,
	}, nil
}

func (s *scheme) UnmarshalTextPublicKey(text []byte) (sign.PublicKey, error) {
	pubKey := new(eddsa.PublicKey)
	err := pubKey.UnmarshalText(text)
	if err != nil {
		return nil, err
	}
	return &publicKey{
		publicKey: pubKey,
	}, nil
}

func (s *scheme) SignatureSize() int {
	return eddsa.SignatureSize
}

func (s *scheme) PublicKeySize() int {
	return eddsa.PublicKeySize
}

func (s *scheme) PrivateKeySize() int {
	return eddsa.PrivateKeySize
}

func (s *scheme) Name() string {
	return "ED25519"
}

type privateKey struct {
	privateKey *eddsa.PrivateKey
}

func (p *privateKey) KeyType() string {
	return "ED25519 PRIVATE KEY"
}

func (p *privateKey) Sign(message []byte) (signature []byte) {
	return p.privateKey.Sign(message)
}

func (p *privateKey) Reset() {
	p.privateKey.Reset()
}

func (p *privateKey) Bytes() []byte {
	return p.privateKey.Bytes()
}

func (p *privateKey) FromBytes(data []byte) error {
	return p.privateKey.FromBytes(data)
}

func (p *privateKey) Identity() []byte {
	return p.privateKey.Identity()
}

type publicKey struct {
	publicKey *eddsa.PublicKey
}

func (p *publicKey) KeyType() string {
	return "ED25519 PUBLIC KEY"
}

func (p *publicKey) Sum256() [32]byte {
	return blake2b.Sum256(p.Bytes())
}

func (p *publicKey) Equal(pubKey sign.PublicKey) bool {
	return hmac.Equal(pubKey.Bytes(), p.Bytes())
}

func (p *publicKey) Verify(signature, message []byte) bool {
	return p.publicKey.Verify(signature, message)
}

func (p *publicKey) Reset() {
	p.publicKey.Reset()
}

func (p *publicKey) Bytes() []byte {
	return p.publicKey.Bytes()
}

func (p *publicKey) FromBytes(data []byte) error {
	return p.publicKey.FromBytes(data)
}

func (p *publicKey) Identity() []byte {
	return p.publicKey.Identity()
}

func (p *publicKey) MarshalText() (text []byte, err error) {
	return []byte(base64.StdEncoding.EncodeToString(p.Bytes())), nil
}

func (p *publicKey) UnmarshalText(text []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}
	return p.FromBytes(raw)
}
