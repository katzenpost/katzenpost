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

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"

	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/utils"
)

var (
	// Scheme implements our sign.Scheme interface using Sphincs+.
	Scheme = &scheme{}

	params = parameters.MakeSphincsPlusSHA256256fRobust(false)
)

type scheme struct{}

var _ sign.Scheme = (*scheme)(nil)

func (s *scheme) NewKeypair() (sign.PrivateKey, sign.PublicKey) {
	privKey, pubKey := sphincs.Spx_keygen(params)
	return &privateKey{
			privateKey: privKey,
		}, &publicKey{
			publicKey: pubKey,
		}
}

func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	pubKey := &publicKey{}
	err := pubKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// UnmarshalBinaryPrivateKey loads a private key from byte slice.
func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	privKey := &privateKey{}
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

// UnmarshalTextPublicKey loads a public key from byte slice.
func (s *scheme) UnmarshalTextPublicKey(text []byte) (sign.PublicKey, error) {
	pubKey := new(publicKey)
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
	return 1234 // XXX FIXME
}

func (s *scheme) PublicKeySize() int {
	return 1234 // XXX FIXME
}

func (s *scheme) SignatureSize() int {
	return 1234 // XXX FIXME
}

type privateKey struct {
	privateKey *sphincs.SPHINCS_SK
}

func (p *privateKey) KeyType() string {
	return "SPHINCS+ PRIVATE KEY"
}

func (p *privateKey) Reset() {
	utils.ExplicitBzero(p.privateKey.SKseed)
	utils.ExplicitBzero(p.privateKey.SKprf)
	utils.ExplicitBzero(p.privateKey.PKseed)
	utils.ExplicitBzero(p.privateKey.PKroot)
}

func (p *privateKey) Bytes() []byte {
	blob, err := p.privateKey.SerializeSK()
	if err != nil {
		panic(err)
	}
	return blob
}

func (p *privateKey) FromBytes(data []byte) error {
	var err error
	p.privateKey, err = sphincs.DeserializeSK(params, data)
	return err
}

func (p *privateKey) Sign(message []byte) (sig []byte) {
	s := sphincs.Spx_sign(params, message, p.privateKey)
	blob, err := s.SerializeSignature()
	if err != nil {
		panic(err)
	}
	return blob
}

type publicKey struct {
	publicKey *sphincs.SPHINCS_PK
}

func newEmptyPublicKey() *publicKey {
	pk := new(sphincs.SPHINCS_PK)
	pk.PKseed = make([]byte, params.N)
	pk.PKroot = []byte{}
	return &publicKey{
		publicKey: pk,
	}
}

func (p *publicKey) KeyType() string {
	return "SPHINCS+ PUBLIC KEY"
}

func (p *publicKey) Reset() {
	utils.ExplicitBzero(p.publicKey.PKseed)
	utils.ExplicitBzero(p.publicKey.PKroot)
}

func (p *publicKey) Bytes() []byte {
	blob, err := p.publicKey.SerializePK()
	if err != nil {
		panic(err)
	}
	return blob
}

func (p *publicKey) FromBytes(data []byte) error {
	var err error
	p.publicKey, err = sphincs.DeserializePK(params, data)
	return err
}

func (p *publicKey) Equal(pubKey sign.PublicKey) bool {
	return hmac.Equal(p.Bytes(), pubKey.Bytes())
}

func (p *publicKey) Verify(sig, message []byte) bool {
	signature, err := sphincs.DeserializeSignature(params, sig)
	if err != nil {
		panic(err)
	}
	return sphincs.Spx_verify(params, message, signature, p.publicKey)
}

func (p *publicKey) Identity() []byte {
	h := p.Sum256()
	return h[:]
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
