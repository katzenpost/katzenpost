//go:build !windows

// SPDX-FileCopyrightText: (c) 2022-2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package sphincsplus implements interface wrapper around a specific parameterization of Sphincs+.
package sphincsplus

import (
	"crypto"
	"crypto/hmac"
	"io"

	"golang.org/x/crypto/blake2b"

	sphincs "github.com/katzenpost/sphincsplus/ref"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/pem"
)

const (
	// KeySeedSize is the seed size used by NewKeyFromSeed to generate
	// a new key deterministically.
	KeySeedSize = 32
)

type scheme struct{}

var sch *scheme = &scheme{}

func Scheme() *scheme { return sch }

var _ sign.Scheme = (*scheme)(nil)
var _ sign.PublicKey = (*publicKey)(nil)
var _ sign.PrivateKey = (*privateKey)(nil)

func (s *scheme) Name() string {
	return "Sphincs+"
}

func (s *scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	priv, pub := sphincs.NewKeypair()
	pubkey := &publicKey{
		scheme:    Scheme(),
		publicKey: pub,
	}
	privkey := &privateKey{
		scheme:     Scheme(),
		publicKey:  pubkey,
		privateKey: priv,
	}
	return pubkey, privkey, nil
}

func (s *scheme) Sign(sk sign.PrivateKey, message []byte, opts *sign.SignatureOpts) []byte {
	sig, err := sk.Sign(nil, message, nil)
	if err != nil {
		panic(err)
	}
	return sig
}

func (s *scheme) Verify(pk sign.PublicKey, message []byte, signature []byte, opts *sign.SignatureOpts) bool {
	return pk.(*publicKey).Verify(signature, message)
}

func (s *scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	// NOTE(david): we use the reference implementation of Sphincs+ which does not
	// have an API that allows for using our own entropy source or seed for key generation.
	// The way to fix this is to use a different implementation of Sphincs+.
	panic("DeriveKey not implemented")
	return nil, nil
}

func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	pubKey := &publicKey{
		publicKey: new(sphincs.PublicKey),
	}
	err := pubKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// UnmarshalBinaryPrivateKey loads a private key from byte slice.
func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	privKey := &privateKey{
		privateKey: new(sphincs.PrivateKey),
	}
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, nil
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

func (s *scheme) SeedSize() int {
	return KeySeedSize
}

func (s *scheme) SupportsContext() bool {
	return false
}

type privateKey struct {
	scheme     *scheme
	privateKey *sphincs.PrivateKey
	publicKey  *publicKey
}

// sign.PublicKey interface

func (p *privateKey) Scheme() sign.Scheme {
	return p.scheme
}

func (p *privateKey) Equal(key crypto.PrivateKey) bool {
	return hmac.Equal(key.(*privateKey).Bytes(), p.Bytes())
}

func (p *privateKey) Public() crypto.PublicKey {
	return p.publicKey
}

func (p *privateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return p.privateKey.Sign(digest), nil
}

func (p *privateKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *privateKey) UnmarshalBinary(b []byte) error {
	return p.FromBytes(b)
}

// end of sign.PublicKey interface

func (p *privateKey) Reset() {
	p.privateKey.Reset()
}

func (p *privateKey) Bytes() []byte {
	return p.privateKey.Bytes()
}

func (p *privateKey) FromBytes(data []byte) error {
	return p.privateKey.FromBytes(data)
}

type publicKey struct {
	scheme    *scheme
	publicKey *sphincs.PublicKey
}

// sign.PublicKey interface

func (p *publicKey) Scheme() sign.Scheme {
	return p.scheme
}

func (p *publicKey) Equal(key crypto.PublicKey) bool {
	return hmac.Equal(key.(*publicKey).Bytes(), p.Bytes())
}

func (p *publicKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *publicKey) MarshalText() (text []byte, err error) {
	return pem.ToPublicPEMBytes(p), nil
}

// end of sign.PublicKey interface

func (p *publicKey) Reset() {
	p.publicKey.Reset()
}

func (p *publicKey) Bytes() []byte {
	return p.publicKey.Bytes()
}

func (p *publicKey) FromBytes(data []byte) error {
	return p.publicKey.FromBytes(data)
}

func (p *publicKey) Verify(sig, message []byte) bool {
	return p.publicKey.Verify(sig, message)
}

func (p *publicKey) Sum256() [32]byte {
	return blake2b.Sum256(p.Bytes())
}
