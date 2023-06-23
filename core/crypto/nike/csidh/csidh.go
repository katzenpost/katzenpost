//go:build !ppc64le

// csidh.go - Adapts csidh module to our NIKE interface.
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

package csidh

import (
	"encoding/base64"
	"errors"
	"io"

	"github.com/henrydcase/nobs/dh/csidh"
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

// CSIDHScheme is the nobs CSIDH-512 NIKE.
var NOBS_CSIDH512Scheme *CsidhNike

var _ nike.PrivateKey = (*PrivateKey)(nil)
var _ nike.PublicKey = (*PublicKey)(nil)
var _ nike.Scheme = (*CsidhNike)(nil)

type CsidhNike struct{}

func (e *CsidhNike) Name() string {
	return "CSIDH-512-nobs"
}

func (e *CsidhNike) PublicKeySize() int {
	return csidh.PublicKeySize
}

func (e *CsidhNike) PrivateKeySize() int {
	return csidh.PrivateKeySize
}

func (e *CsidhNike) GeneratePrivateKey(rng io.Reader) nike.PrivateKey {
	privateKey := new(csidh.PrivateKey)
	err := csidh.GeneratePrivateKey(privateKey, rand.Reader)
	if err != nil {
		panic(err)
	}
	return &PrivateKey{
		privateKey: privateKey,
	}
}

func (e *CsidhNike) GenerateKeyPairFromEntropy(rng io.Reader) (nike.PublicKey, nike.PrivateKey, error) {
	privateKey := new(csidh.PrivateKey)
	err := csidh.GeneratePrivateKey(privateKey, rng)
	if err != nil {
		return nil, nil, err
	}
	privKey := &PrivateKey{
		privateKey: privateKey,
	}
	publicKey := e.DerivePublicKey(privKey)
	return publicKey, privKey, nil
}

func (e *CsidhNike) GenerateKeyPair() (nike.PublicKey, nike.PrivateKey, error) {
	privateKey := new(csidh.PrivateKey)
	err := csidh.GeneratePrivateKey(privateKey, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privKey := &PrivateKey{
		privateKey: privateKey,
	}
	publicKey := e.DerivePublicKey(privKey)
	return publicKey, privKey, nil
}

func (e *CsidhNike) DeriveSecret(privKey nike.PrivateKey, pubKey nike.PublicKey) []byte {
	sharedSecret := &[64]byte{}
	ok := csidh.DeriveSecret(sharedSecret, pubKey.(*PublicKey).publicKey, privKey.(*PrivateKey).privateKey, rand.Reader)
	if !ok {
		panic("csidh.DeriveSecret failed!")
	}
	return sharedSecret[:]
}

func (e *CsidhNike) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	pubKey := new(csidh.PublicKey)
	csidh.GeneratePublicKey(pubKey, privKey.(*PrivateKey).privateKey, rand.Reader)
	return &PublicKey{
		publicKey: pubKey,
	}
}

func (e CsidhNike) Blind(groupMember nike.PublicKey, blindingFactor nike.PrivateKey) (blindedGroupMember nike.PublicKey) {
	panic("Blind operation no implemented")
}

func (e *CsidhNike) NewEmptyPublicKey() nike.PublicKey {
	return &PublicKey{
		publicKey: new(csidh.PublicKey),
	}
}

func (e *CsidhNike) NewEmptyPrivateKey() nike.PrivateKey {
	return &PrivateKey{
		privateKey: new(csidh.PrivateKey),
	}
}

func (e *CsidhNike) UnmarshalBinaryPublicKey(b []byte) (nike.PublicKey, error) {
	pubKey := new(csidh.PublicKey)
	ok := pubKey.Import(b)
	if !ok {
		return nil, errors.New("CSIDH public key import failure")
	}
	return &PublicKey{
		publicKey: pubKey,
	}, nil
}

func (e *CsidhNike) UnmarshalBinaryPrivateKey(b []byte) (nike.PrivateKey, error) {
	privKey := new(csidh.PrivateKey)
	ok := privKey.Import(b)
	if !ok {
		return nil, errors.New("CSIDH private key import failure")
	}
	return &PrivateKey{
		privateKey: privKey,
	}, nil
}

type PublicKey struct {
	publicKey *csidh.PublicKey
}

func (p *PublicKey) Blind(blindingFactor nike.PrivateKey) error {
	panic("Blind operation no implemented")
}

func (p *PublicKey) Reset() {
	p.publicKey = nil
}

func (p *PublicKey) Bytes() []byte {
	s := make([]byte, csidh.PublicKeySize)
	p.publicKey.Export(s)
	return s
}

func (p *PublicKey) FromBytes(b []byte) error {
	ok := p.publicKey.Import(b)
	if !ok {
		return errors.New("csidh public key import failure")
	}
	return nil
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
	privateKey *csidh.PrivateKey
}

func (p *PrivateKey) Public() nike.PublicKey {
	pubKey := new(csidh.PublicKey)
	csidh.GeneratePublicKey(pubKey, p.privateKey, rand.Reader)
	return &PublicKey{
		publicKey: pubKey,
	}
}

func (p *PrivateKey) Reset() {
	p.privateKey = nil
}

func (p *PrivateKey) Bytes() []byte {
	s := make([]byte, csidh.PrivateKeySize)
	p.privateKey.Export(s)
	return s
}

func (p *PrivateKey) FromBytes(b []byte) error {
	ok := p.privateKey.Import(b)
	if !ok {
		return errors.New("csidh private key import failure")
	}
	return nil
}

func (p *PrivateKey) MarshalBinary() ([]byte, error) {
	s := make([]byte, csidh.PrivateKeySize)
	ok := p.privateKey.Export(s)
	if !ok {
		return nil, errors.New("MarshalBinary fail")
	}
	return s, nil
}

func (p *PrivateKey) UnmarshalBinary(data []byte) error {
	return p.FromBytes(data)
}

func (p *PrivateKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(p.Bytes())), nil
}

func (p *PrivateKey) UnmarshalText(data []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}
	return p.FromBytes(raw)
}

func init() {
	NOBS_CSIDH512Scheme = new(CsidhNike)
}
