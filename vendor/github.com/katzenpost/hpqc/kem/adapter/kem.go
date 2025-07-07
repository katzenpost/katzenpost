// SPDX-FileCopyrightText: Copyright (C) 2022-2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package adapter provides an adhoc hashed ElGamal construction
// that essentially acts like an adapter, adapting a NIKE to KEM.
package adapter

import (
	"crypto/hmac"
	"fmt"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/nike"
)

const (
	// SeedSize is the number of bytes needed to seed deterministic methods below.
	SeedSize = 32
)

var _ kem.PrivateKey = (*PrivateKey)(nil)
var _ kem.PublicKey = (*PublicKey)(nil)
var _ kem.Scheme = (*Scheme)(nil)

// PublicKey is an adapter for nike.PublicKey to kem.PublicKey.
type PublicKey struct {
	publicKey nike.PublicKey
	scheme    *Scheme
}

func (p *PublicKey) Scheme() kem.Scheme {
	return p.scheme
}

func (p *PublicKey) MarshalText() (text []byte, err error) {
	return pem.ToPublicPEMBytes(p), nil
}

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	return p.publicKey.MarshalBinary()
}

func (p *PublicKey) Equal(pubkey kem.PublicKey) bool {
	if pubkey.(*PublicKey).scheme != p.scheme {
		return false
	}
	return hmac.Equal(pubkey.(*PublicKey).publicKey.Bytes(), p.publicKey.Bytes())
}

// PrivateKey is an adapter for nike.PrivateKey to kem.PrivateKey.
type PrivateKey struct {
	privateKey nike.PrivateKey
	scheme     *Scheme
}

func (p *PrivateKey) Scheme() kem.Scheme {
	return p.scheme
}

func (p *PrivateKey) MarshalBinary() ([]byte, error) {
	return p.privateKey.MarshalBinary()
}

func (p *PrivateKey) Equal(privkey kem.PrivateKey) bool {
	if privkey.(*PrivateKey).scheme != p.scheme {
		return false
	}
	return hmac.Equal(privkey.(*PrivateKey).privateKey.Bytes(), p.privateKey.Bytes())
}

func (p *PrivateKey) Public() kem.PublicKey {
	return &PublicKey{
		publicKey: p.privateKey.Public(),
		scheme:    p.scheme,
	}
}

// Scheme is an adapter for nike.Scheme to kem.Scheme.
// See docs/specs/kemsphinx.rst for some design notes
// on this NIKE to KEM adapter.
type Scheme struct {
	nike nike.Scheme
}

var _ kem.Scheme = (*Scheme)(nil)
var _ kem.PublicKey = (*PublicKey)(nil)
var _ kem.PrivateKey = (*PrivateKey)(nil)

// FromNIKE creates a new KEM adapter Scheme
// using the given NIKE Scheme.
func FromNIKE(nike nike.Scheme) kem.Scheme {
	if nike == nil {
		return nil
	}
	return &Scheme{
		nike: nike,
	}
}

// Name of the scheme
func (a *Scheme) Name() string {
	return a.nike.Name()
}

// GenerateKeyPair creates a new key pair.
func (a *Scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	pubkey, privkey, err := a.nike.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{
			publicKey: pubkey,
			scheme:    a,
		}, &PrivateKey{
			privateKey: privkey,
			scheme:     a,
		}, nil
}

// Encapsulate generates a shared key ss for the public key and
// encapsulates it into a ciphertext ct.
func (a *Scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	theirPubkey, ok := pk.(*PublicKey)
	if !ok || theirPubkey.scheme != a {
		return nil, nil, kem.ErrTypeMismatch
	}
	myPubkey, sk2, err := a.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	// ss = DH(my_privkey, their_pubkey)
	ss = a.nike.DeriveSecret(sk2.(*PrivateKey).privateKey, theirPubkey.publicKey)
	// ss2 = H(ss || their_pubkey || my_pubkey)
	ss2 := a.hash(ss, theirPubkey.publicKey.Bytes(), myPubkey.(*PublicKey).publicKey.Bytes())
	ct, _ = myPubkey.MarshalBinary()
	return ct, ss2, nil
}

func (a *Scheme) hash(ss []byte, pubkey1 []byte, pubkey2 []byte) []byte {
	var h blake2b.XOF
	var err error
	if len(ss) != 32 {
		sum := blake2b.Sum256(ss)
		h, err = blake2b.NewXOF(uint32(a.SharedKeySize()), sum[:])
	} else {
		h, err = blake2b.NewXOF(uint32(a.SharedKeySize()), ss)
	}
	if err != nil {
		panic(err)
	}
	_, err = h.Write(pubkey1)
	if err != nil {
		panic(err)
	}
	_, err = h.Write(pubkey2)
	if err != nil {
		panic(err)
	}
	ss2 := make([]byte, len(ss))
	_, err = h.Read(ss2)
	if err != nil {
		panic(err)
	}
	return ss2
}

// Returns the shared key encapsulated in ciphertext ct for the
// private key sk.
// Implements DECAPSULATE as described in NIKE to KEM adapter,
// see docs/specs/kemsphinx.rst
func (a *Scheme) Decapsulate(myPrivkey kem.PrivateKey, ct []byte) ([]byte, error) {
	if len(ct) != a.CiphertextSize() {
		return nil, kem.ErrCiphertextSize
	}
	theirPubkey, err := a.UnmarshalBinaryPublicKey(ct)
	if err != nil {
		return nil, err
	}
	// s = DH(my_privkey, their_pubkey)
	ss := a.nike.DeriveSecret(myPrivkey.(*PrivateKey).privateKey, theirPubkey.(*PublicKey).publicKey)
	// shared_key = H(ss || my_pubkey || their_pubkey)
	ss2 := a.hash(ss, myPrivkey.Public().(*PublicKey).publicKey.Bytes(), theirPubkey.(*PublicKey).publicKey.Bytes())
	return ss2, nil
}

// Unmarshals a PublicKey from the provided buffer.
func (a *Scheme) UnmarshalBinaryPublicKey(b []byte) (kem.PublicKey, error) {
	if len(b) != a.PublicKeySize() {
		return nil, fmt.Errorf("UnmarshalBinaryPublicKey: wrong key size %d != %d", len(b), a.PublicKeySize())
	}
	pubkey, err := a.nike.UnmarshalBinaryPublicKey(b)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		publicKey: pubkey,
		scheme:    a,
	}, nil
}

// Unmarshals a PrivateKey from the provided buffer.
func (a *Scheme) UnmarshalBinaryPrivateKey(b []byte) (kem.PrivateKey, error) {
	if len(b) != a.PrivateKeySize() {
		return nil, fmt.Errorf("UnmarshalBinaryPrivateKey: wrong key size %d != %d", len(b), a.PrivateKeySize())
	}
	privkey, err := a.nike.UnmarshalBinaryPrivateKey(b)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		privateKey: privkey,
		scheme:     a,
	}, nil
}

func (a *Scheme) UnmarshalTextPublicKey(text []byte) (kem.PublicKey, error) {
	return pem.FromPublicPEMBytes(text, a)
}

func (a *Scheme) UnmarshalTextPrivateKey(text []byte) (kem.PrivateKey, error) {
	return pem.FromPrivatePEMBytes(text, a)
}

// Size of encapsulated keys.
func (a *Scheme) CiphertextSize() int {
	return a.nike.PublicKeySize()
}

// Size of established shared keys.
func (a *Scheme) SharedKeySize() int {
	return a.nike.PublicKeySize()
}

// Size of packed private keys.
func (a *Scheme) PrivateKeySize() int {
	return a.nike.PrivateKeySize()
}

// Size of packed public keys.
func (a *Scheme) PublicKeySize() int {
	return a.nike.PublicKeySize()
}

// DeriveKeyPair deterministically derives a pair of keys from a seed.
// Panics if the length of seed is not equal to the value returned by
// SeedSize.
func (a *Scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != a.SeedSize() {
		panic(fmt.Errorf("%s: provided len(seed) %d != a.SeedSize() %d", kem.ErrSeedSize, len(seed), a.SeedSize()))
	}
	h, err := blake2b.NewXOF(0, nil)
	if err != nil {
		panic(err)
	}

	seedHash := blake2b.Sum256(seed)
	count, err := h.Write(seedHash[:])
	if err != nil {
		panic(err)
	}
	if count != len(seedHash) {
		panic("blake2b.XOR failed")
	}
	pk, sk, err := a.nike.GenerateKeyPairFromEntropy(h)
	if err != nil {
		panic(err)
	}
	return &PublicKey{
			publicKey: pk,
			scheme:    a,
		}, &PrivateKey{
			privateKey: sk,
			scheme:     a,
		}
}

// Size of seed used in DeriveKey
func (a *Scheme) SeedSize() int {
	return SeedSize
}

// EncapsulateDeterministically generates a shared key ss for the public
// key deterministically from the given seed and encapsulates it into
// a ciphertext ct. If unsure, you're better off using Encapsulate().
// Implements ENCAPSULATE as described in NIKE to KEM adapter,
// see docs/specs/kemsphinx.rst
func (a *Scheme) EncapsulateDeterministically(pk kem.PublicKey, seed []byte) (
	ct, ss []byte, err error) {
	panic("not implemented")
}
