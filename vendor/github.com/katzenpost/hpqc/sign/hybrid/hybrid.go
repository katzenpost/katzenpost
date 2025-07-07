// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package hybrid

import (
	"crypto"
	"crypto/hmac"
	"io"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/pem"
)

// Scheme is for hybrid signature schemes.
type Scheme struct {
	name   string
	first  sign.Scheme
	second sign.Scheme
}

var _ sign.Scheme = (*Scheme)(nil)
var _ sign.PrivateKey = (*PrivateKey)(nil)
var _ sign.PublicKey = (*PublicKey)(nil)

// New creates a new hybrid signature scheme given the two signature schemes,
// assumign one of them is classical and the other post quantum.
func New(name string, first sign.Scheme, second sign.Scheme) sign.Scheme {
	return &Scheme{
		name:   name,
		first:  first,
		second: second,
	}
}

func (s *Scheme) Name() string {
	return s.name
}

func (s *Scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	pub1, priv1, err := s.first.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	pub2, priv2, err := s.second.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{
			scheme: s,
			first:  pub1,
			second: pub2,
		}, &PrivateKey{
			scheme: s,
			first:  priv1,
			second: priv2,
		}, nil
}

func (s *Scheme) Sign(sk sign.PrivateKey, message []byte, opts *sign.SignatureOpts) []byte {
	return append(s.first.Sign(sk.(*PrivateKey).first, message, opts),
		s.second.Sign(sk.(*PrivateKey).second, message, opts)...)
}

func (s *Scheme) Verify(pk sign.PublicKey, message []byte, signature []byte, opts *sign.SignatureOpts) bool {
	if len(signature) != s.SignatureSize() {
		panic("incorrect signature size")
	}
	if !s.first.Verify(pk.(*PublicKey).first, message, signature[:s.first.SignatureSize()], opts) {
		return false
	}
	if !s.second.Verify(pk.(*PublicKey).second, message, signature[s.first.SignatureSize():], opts) {
		return false
	}
	return true
}

func (s *Scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	if len(seed) != s.SeedSize() {
		panic("wrong seed size")
	}
	pub1, priv1 := s.first.DeriveKey(seed[:s.first.SeedSize()])
	pub2, priv2 := s.second.DeriveKey(seed[s.first.SeedSize():])
	return &PublicKey{
			scheme: s,
			first:  pub1,
			second: pub2,
		}, &PrivateKey{
			scheme: s,
			first:  priv1,
			second: priv2,
		}
}

func (s *Scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	pub1, err := s.first.UnmarshalBinaryPublicKey(b[:s.first.PublicKeySize()])
	if err != nil {
		return nil, err
	}
	pub2, err := s.second.UnmarshalBinaryPublicKey(b[s.first.PublicKeySize():])
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		scheme: s,
		first:  pub1,
		second: pub2,
	}, nil
}

func (s *Scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	priv1, err := s.first.UnmarshalBinaryPrivateKey(b[:s.first.PrivateKeySize()])
	if err != nil {
		return nil, err
	}
	priv2, err := s.second.UnmarshalBinaryPrivateKey(b[s.first.PrivateKeySize():])
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		scheme: s,
		first:  priv1,
		second: priv2,
	}, nil
}

func (s *Scheme) PublicKeySize() int {
	return s.first.PublicKeySize() + s.second.PublicKeySize()
}

func (s *Scheme) PrivateKeySize() int {
	return s.first.PrivateKeySize() + s.second.PrivateKeySize()
}

func (s *Scheme) SignatureSize() int {
	return s.first.SignatureSize() + s.second.SignatureSize()
}

func (s *Scheme) SeedSize() int {
	return s.first.SeedSize() + s.second.SeedSize()
}

func (s *Scheme) SupportsContext() bool {
	if !s.first.SupportsContext() {
		return false
	}
	if !s.second.SupportsContext() {
		return false
	}
	return true
}

// PrivateKey is the private key in hybrid signature scheme.
type PrivateKey struct {
	scheme    *Scheme
	publicKey *PublicKey
	first     sign.PrivateKey
	second    sign.PrivateKey
}

func (p *PrivateKey) Scheme() sign.Scheme {
	return p.scheme
}

func (p *PrivateKey) Equal(key crypto.PrivateKey) bool {
	blob1, err := p.MarshalBinary()
	if err != nil {
		panic(err)
	}
	blob2, err := key.(*PrivateKey).MarshalBinary()
	if err != nil {
		panic(err)
	}
	return hmac.Equal(blob1, blob2)
}

func (p *PrivateKey) Public() crypto.PublicKey {
	panic("not implemented")
}

func (p *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	sig1, err := p.first.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}
	sig2, err := p.second.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}
	return append(sig1, sig2...), nil
}

func (p *PrivateKey) MarshalBinary() ([]byte, error) {
	blob1, err := p.first.MarshalBinary()
	if err != nil {
		return nil, err
	}
	blob2, err := p.second.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(blob1, blob2...), nil
}

func (p *PrivateKey) UnmarshalBinary(b []byte) error {
	err := p.first.UnmarshalBinary(b[:p.first.Scheme().PrivateKeySize()])
	if err != nil {
		return err
	}
	return p.second.UnmarshalBinary(b[p.first.Scheme().PrivateKeySize():])
}

// PublicKey is the public key in hybrid signature scheme.
type PublicKey struct {
	scheme *Scheme
	first  sign.PublicKey
	second sign.PublicKey
}

func (p *PublicKey) Scheme() sign.Scheme {
	return p.scheme
}

func (p *PublicKey) Equal(key crypto.PublicKey) bool {
	blob1, err := p.MarshalBinary()
	if err != nil {
		panic(err)
	}
	var blob2 []byte
	switch v := key.(type) {
	case []byte:
		blob2 = v
	case *PublicKey:
		blob2, err = v.MarshalBinary()
		if err != nil {
			panic(err)
		}
	default:
		panic("type assertion failed")
	}
	return hmac.Equal(blob1, blob2)
}

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	blob1, err := p.first.MarshalBinary()
	if err != nil {
		return nil, err
	}
	blob2, err := p.second.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(blob1, blob2...), nil
}

func (p *PublicKey) MarshalText() (text []byte, err error) {
	return pem.ToPublicPEMBytes(p), nil
}
