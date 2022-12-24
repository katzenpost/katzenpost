// sphincs.go - Implements interface wrapper around a specific parameterization of Sphincs+.
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

// Package sphincsplus implements interface wrapper around a specific parameterization of Sphincs+.
package sphincsplus

import (
	"crypto/hmac"
	"encoding/base64"

	"golang.org/x/crypto/blake2b"

	sphincs "github.com/katzenpost/katzenpost/sphincsplus/ref"

	"github.com/katzenpost/katzenpost/core/crypto/sign"
)

var (
	// Scheme implements our sign.Scheme interface using Sphincs+.
	Scheme = &scheme{}
)

type scheme struct{}

var _ sign.Scheme = (*scheme)(nil)
var _ sign.PublicKey = (*publicKey)(nil)
var _ sign.PrivateKey = (*privateKey)(nil)

func (s *scheme) NewKeypair() (sign.PrivateKey, sign.PublicKey) {
	privKey, pubKey := sphincs.NewKeypair()
	return &privateKey{
			privateKey: privKey,
		}, &publicKey{
			publicKey: pubKey,
		}
}

// NewEmptyPublicKey returns an empty sign.PublicKey
func (s *scheme) NewEmptyPublicKey() sign.PublicKey {
	return NewEmptyPublicKey()
}

func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	pubKey := NewEmptyPublicKey()
	err := pubKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// UnmarshalBinaryPrivateKey loads a private key from byte slice.
func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	privKey := NewEmptyPrivateKey()
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

// UnmarshalTextPublicKey loads a public key from byte slice.
func (s *scheme) UnmarshalTextPublicKey(text []byte) (sign.PublicKey, error) {
	pubKey := NewEmptyPublicKey()
	err := pubKey.UnmarshalText(text)
	if err != nil {
		return nil, err
	}
	return pubKey, nil

}

func (s *scheme) Name() string {
	return "Sphincs+"
}

func (s *scheme) PrivateKeySize() int {
	return sphincs.PrivateKeySize
}

func (s *scheme) PublicKeySize() int {
	return sphincs.PublicKeySize
}

func (s *scheme) SignatureSize() int {
	return sphincs.SignatureSize
}

type privateKey struct {
	privateKey *sphincs.PrivateKey
}

func NewEmptyPrivateKey() *privateKey {
	return &privateKey{
		privateKey: new(sphincs.PrivateKey),
	}
}

func (p *privateKey) KeyType() string {
	return "SPHINCS+ PRIVATE KEY"
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

func (p *privateKey) Sign(message []byte) (sig []byte) {
	return p.privateKey.Sign(message)
}

type publicKey struct {
	publicKey *sphincs.PublicKey
}

func NewEmptyPublicKey() *publicKey {
	return &publicKey{
		publicKey: new(sphincs.PublicKey),
	}
}

func (p *publicKey) KeyType() string {
	return "SPHINCS+ PUBLIC KEY"
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

func (p *publicKey) Equal(pubKey sign.PublicKey) bool {
	return hmac.Equal(p.Bytes(), pubKey.Bytes())
}

func (p *publicKey) Verify(sig, message []byte) bool {
	return p.publicKey.Verify(sig, message)
}

func (p *publicKey) Sum256() [32]byte {
	return blake2b.Sum256(p.Bytes())
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
func (p *publicKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *publicKey) UnmarshalBinary(data []byte) error {
	return p.FromBytes(data)
}
