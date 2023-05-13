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
// +build ppc64le

package csidh

import (
	"encoding/base64"
	"errors"
	"io"

	//"github.com/henrydcase/nobs/dh/csidh" // does not support ppc64le
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

// CSIDHScheme is the nobs CSIDH-512 NIKE.
var CSIDHScheme *CsidhNike

var _ nike.PrivateKey = (*PrivateKey)(nil)
var _ nike.PublicKey = (*PublicKey)(nil)
var _ nike.Scheme = (*CsidhNike)(nil)

type CsidhNike struct{}

func (e *CsidhNike) Name() string {
	return "CSIDH-512-nobs"
}

func (e *CsidhNike) PublicKeySize() int {
	panic("NotImplemented")
	return 0
}

func (e *CsidhNike) PrivateKeySize() int {
	panic("NotImplemented")
	return 0
}

func (e *CsidhNike) GeneratePrivateKey(rng io.Reader) nike.PrivateKey {
	panic("NotImplemented")
	return &PrivateKey{}
}

func (e *CsidhNike) GenerateKeyPairFromEntropy(rng io.Reader) (nike.PublicKey, nike.PrivateKey, error) {
	panic("NotImplemented")
	privKey := &PrivateKey{}
	publicKey := &PublicKey{}
	return publicKey, privKey, nil
}

func (e *CsidhNike) GenerateKeyPair() (nike.PublicKey, nike.PrivateKey, error) {
	panic("NotImplemented")
	privKey := &PrivateKey{}
	publicKey := &PublicKey{}
	return publicKey, privKey, nil
}

func (e *CsidhNike) DeriveSecret(privKey nike.PrivateKey, pubKey nike.PublicKey) []byte {
	panic("NotImplemented")
	return make([]byte,0)
}

func (e *CsidhNike) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	panic("NotImplemented")
	return &PublicKey{}
}

func (e CsidhNike) Blind(groupMember nike.PublicKey, blindingFactor nike.PrivateKey) (blindedGroupMember nike.PublicKey) {
	panic("Blind operation no implemented")
}

func (e *CsidhNike) NewEmptyPublicKey() nike.PublicKey {
	panic("NotImplemented")
	return &PublicKey{}
}

func (e *CsidhNike) NewEmptyPrivateKey() nike.PrivateKey {
	panic("NotImplemented")
	return &PrivateKey{}
}

func (e *CsidhNike) UnmarshalBinaryPublicKey(b []byte) (nike.PublicKey, error) {
	panic("NotImplemented")
	return &PublicKey{}, nil
}

func (e *CsidhNike) UnmarshalBinaryPrivateKey(b []byte) (nike.PrivateKey, error) {
	panic("NotImplemented")
	return &PrivateKey{}, nil
}

type PublicKey struct {
	publicKey *csidh.PublicKey
}

func (p *PublicKey) Blind(blindingFactor nike.PrivateKey) error {
	panic("Blind operation no implemented")
}

func (p *PublicKey) Reset() {
	p.publicKey = nil
	p = nil
}

func (p *PublicKey) Bytes() []byte {
	panic("NotImplemented")
	return make([]byte, 0)
}

func (p *PublicKey) FromBytes(b []byte) error {
	panic("NotImplemented")
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (p *PublicKey) MarshalBinary() ([]byte, error) {
	panic("NotImplemented")
	return make([]byte, 0), nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (p *PublicKey) UnmarshalBinary(data []byte) error {
	panic("NotImplemented")
	return nil
}

// MarshalText is an implementation of a method on the
// TextMarshaler interface defined in https://golang.org/pkg/encoding/
func (p *PublicKey) MarshalText() ([]byte, error) {
	panic("NotImplemented")
	return make([]byte, 0), nil
}

// UnmarshalText is an implementation of a method on the
// TextUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (p *PublicKey) UnmarshalText(data []byte) error {
	panic("NotImplemented")
	return nil
}

type PrivateKey struct {}

func (p *PrivateKey) Public() nike.PublicKey {
	panic("NotImplemented"
	return &PublicKey{}
}

func (p *PrivateKey) Reset() {
	panic("NotImplemented")
}

func (p *PrivateKey) Bytes() []byte {
	s := make([]byte, csidh.PrivateKeySize)
	p.privateKey.Export(s)
	return s
}

func (p *PrivateKey) FromBytes(b []byte) error {
	return nil
}

func (p *PrivateKey) MarshalBinary() ([]byte, error) {
	panic("NotImplemented")
	return make([]byte, 0), nil
}

func (p *PrivateKey) UnmarshalBinary(data []byte) error {
	panic("NotImplemented")
	return nil
}

func (p *PrivateKey) MarshalText() ([]byte, error) {
	panic("NotImplemented")
	return make([]byte, 0), nil
}

func (p *PrivateKey) UnmarshalText(data []byte) error {
	panic("NotImplemented")
	return nil
}

func init() {
	CSIDHScheme = new(CsidhNike)
}
