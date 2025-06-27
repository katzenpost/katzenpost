// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package xwing provides the xwing KEM using a KEM wrapper
// so that it obeys our KEM interfaces for Scheme, PrivateKey, PublicKey.
package xwing

import (
	"crypto/hmac"
	"errors"

	"filippo.io/mlkem768/xwing"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/pem"
)

const (
	KeySeedSize    = xwing.SeedSize
	SharedKeySize  = xwing.SharedKeySize
	CiphertextSize = xwing.CiphertextSize
	PublicKeySize  = xwing.EncapsulationKeySize
	PrivateKeySize = PublicKeySize + xwing.DecapsulationKeySize
)

// tell the type checker that we obey these interfaces
var _ kem.Scheme = (*scheme)(nil)
var _ kem.PublicKey = (*PublicKey)(nil)
var _ kem.PrivateKey = (*PrivateKey)(nil)

var sch kem.Scheme = &scheme{}

// Scheme returns a KEM interface.
func Scheme() kem.Scheme { return sch }

type PublicKey struct {
	scheme   *scheme
	encapKey []byte
}

func (p *PublicKey) Scheme() kem.Scheme {
	return p.scheme
}

func (p *PublicKey) MarshalText() (text []byte, err error) {
	return pem.ToPublicPEMBytes(p), nil
}

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	return p.encapKey, nil
}

func (p *PublicKey) Equal(pubkey kem.PublicKey) bool {
	if pubkey.(*PublicKey).scheme != p.scheme {
		return false
	}
	return hmac.Equal(pubkey.(*PublicKey).encapKey, p.encapKey)
}

type PrivateKey struct {
	scheme   *scheme
	decapKey []byte
	encapKey []byte
}

func (p *PrivateKey) Scheme() kem.Scheme {
	return p.scheme
}

func (p *PrivateKey) MarshalBinary() ([]byte, error) {
	return append(p.decapKey, p.encapKey...), nil
}

func (p *PrivateKey) Equal(privkey kem.PrivateKey) bool {
	if privkey.(*PrivateKey).scheme != p.scheme {
		return false
	}
	return hmac.Equal(privkey.(*PrivateKey).decapKey, p.decapKey)
}

func (p *PrivateKey) Public() kem.PublicKey {
	return &PublicKey{
		encapKey: p.encapKey,
		scheme:   p.scheme,
	}
}

type scheme struct {
}

func (s *scheme) Name() string {
	return "XWING"
}

func (a *scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	encapKey, decapKey, err := xwing.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{
			scheme:   a,
			encapKey: encapKey,
		}, &PrivateKey{
			scheme:   a,
			encapKey: encapKey,
			decapKey: decapKey,
		}, nil
}

func (s *scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	return xwing.Encapsulate(pk.(*PublicKey).encapKey)
}

func (s *scheme) Decapsulate(myPrivkey kem.PrivateKey, ct []byte) ([]byte, error) {
	return xwing.Decapsulate(myPrivkey.(*PrivateKey).decapKey, ct)
}

func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (kem.PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, errors.New("wrong key size")
	}
	return &PublicKey{
		scheme:   s,
		encapKey: b,
	}, nil
}

func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (kem.PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return nil, errors.New("wrong key size")
	}
	return &PrivateKey{
		scheme:   s,
		decapKey: b[:xwing.DecapsulationKeySize],
		encapKey: b[xwing.DecapsulationKeySize:],
	}, nil
}

func (s *scheme) UnmarshalTextPublicKey(text []byte) (kem.PublicKey, error) {
	return pem.FromPublicPEMBytes(text, s)
}

func (s *scheme) UnmarshalTextPrivateKey(text []byte) (kem.PrivateKey, error) {
	return pem.FromPrivatePEMBytes(text, s)
}

func (s *scheme) CiphertextSize() int {
	return CiphertextSize
}

func (s *scheme) SharedKeySize() int {
	return SharedKeySize
}

func (s *scheme) PrivateKeySize() int {
	return PrivateKeySize
}

func (s *scheme) PublicKeySize() int {
	return PublicKeySize
}

func (s *scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != KeySeedSize {
		panic(kem.ErrSeedSize)
	}
	encapKey, decapKey, err := xwing.NewKeyFromSeed(seed)
	if err != nil {
		panic(err)
	}
	return &PublicKey{
			scheme:   s,
			encapKey: encapKey,
		}, &PrivateKey{
			scheme:   s,
			encapKey: encapKey,
			decapKey: decapKey,
		}
}

func (s *scheme) SeedSize() int {
	return KeySeedSize
}
