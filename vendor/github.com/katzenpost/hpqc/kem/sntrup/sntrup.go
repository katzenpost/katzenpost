// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// This package provide the Streamlined NTRU Prime KEM.
package sntrup

import (
	"crypto/hmac"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/pem"

	sntrup "github.com/katzenpost/sntrup4591761"

	"github.com/katzenpost/hpqc/rand"
)

const (
	// PublicKeySize is the public key size in bytes.
	PublicKeySize = sntrup.PublicKeySize

	// PrivateKeySize is the private key size in bytes.
	PrivateKeySize = sntrup.PrivateKeySize

	// SharedKeySize is the size of the shared key in bytes.
	SharedKeySize = sntrup.SharedKeySize

	// CiphertextSize is the size of the ciphertext in bytes.
	CiphertextSize = sntrup.CiphertextSize

	// KeySeedSize is currently set to 32 but should be adjusted
	// to our security bits.
	KeySeedSize = 32

	// EncapsulationSeedSize is currently set to 32 but should be adjusted
	// to our security bits.
	EncapsulationSeedSize = 32
)

var kdfKeyGenInfo = []byte("katzenpost-kem-sntrup-hkdf-blake2b-keygen")
var kdfEncapInfo = []byte("katzenpost-kem-sntrup-hkdf-blake2b-encap")

func newKDF(seed, info []byte) io.Reader {
	blakeHash := func() hash.Hash {
		h, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		return h
	}

	return hkdf.New(blakeHash, nil, seed, info)
}

// Public key of a hybrid KEM.
type PublicKey struct {
	scheme *scheme
	key    *sntrup.PublicKey
}

// Private key of a hybrid KEM.
type PrivateKey struct {
	scheme *scheme
	key    *sntrup.PrivateKey
}

// NewKeyFromSeed derives a public/private keypair deterministically
// from the given seed.
//
// Panics if seed is not of length KeySeedSize.
func NewKeyFromSeed(seed []byte) (*PublicKey, *PrivateKey) {
	if len(seed) != KeySeedSize {
		panic("seed must be of length KeySeedSize")
	}

	pubKey, privKey, err := sntrup.GenerateKey(newKDF(seed, kdfKeyGenInfo))

	if err != nil {
		panic(err)
	}

	return &PublicKey{
			scheme: &scheme{},
			key:    pubKey,
		}, &PrivateKey{
			scheme: &scheme{},
			key:    privKey,
		}
}

// GenerateKeyPair generates public and private keys using entropy from rand.
// If rand is nil, hpqc/rand.Reader will be used.
func GenerateKeyPair(rng io.Reader) (*PublicKey, *PrivateKey, error) {
	var seed [KeySeedSize]byte
	if rng == nil {
		rng = rand.Reader
	}
	_, err := io.ReadFull(rng, seed[:])
	if err != nil {
		return nil, nil, err
	}
	pk, sk := NewKeyFromSeed(seed[:])
	return pk, sk, nil
}

type scheme struct{}

var sch kem.Scheme = &scheme{}

// Scheme returns a KEM interface.
func Scheme() kem.Scheme { return sch }

func (*scheme) Name() string               { return "sntrup4591761" }
func (*scheme) PublicKeySize() int         { return PublicKeySize }
func (*scheme) PrivateKeySize() int        { return PrivateKeySize }
func (*scheme) SeedSize() int              { return KeySeedSize }
func (*scheme) SharedKeySize() int         { return SharedKeySize }
func (*scheme) CiphertextSize() int        { return CiphertextSize }
func (*scheme) EncapsulationSeedSize() int { return EncapsulationSeedSize }

func (*scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	return GenerateKeyPair(rand.Reader)
}

func (*scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != KeySeedSize {
		panic(kem.ErrSeedSize)
	}
	return NewKeyFromSeed(seed[:])
}

func (*scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	ct = make([]byte, CiphertextSize)
	ss = make([]byte, SharedKeySize)

	pub, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}
	pub.EncapsulateTo(ct, ss, nil)
	return
}

func (*scheme) EncapsulateDeterministically(pk kem.PublicKey, seed []byte) (
	ct, ss []byte, err error) {
	if len(seed) != EncapsulationSeedSize {
		return nil, nil, kem.ErrSeedSize
	}

	ct = make([]byte, CiphertextSize)
	ss = make([]byte, SharedKeySize)

	pub, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}
	pub.EncapsulateTo(ct, ss, seed)
	return
}

func (*scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	if len(ct) != CiphertextSize {
		return nil, kem.ErrCiphertextSize
	}

	priv, ok := sk.(*PrivateKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}
	ss := make([]byte, SharedKeySize)
	priv.DecapsulateTo(ss, ct)
	return ss, nil
}

func (s *scheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
	if len(buf) != PublicKeySize {
		return nil, kem.ErrPubKeySize
	}
	pubKey := new(sntrup.PublicKey)
	copy(pubKey[:], buf)
	return &PublicKey{
		scheme: s,
		key:    pubKey,
	}, nil
}

func (s *scheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
	if len(buf) != PrivateKeySize {
		return nil, kem.ErrPrivKeySize
	}
	privKey := new(sntrup.PrivateKey)
	copy(privKey[:], buf)
	return &PrivateKey{
		scheme: s,
		key:    privKey,
	}, nil
}

func (s *scheme) UnmarshalTextPublicKey(text []byte) (kem.PublicKey, error) {
	return pem.FromPublicPEMBytes(text, s)
}

func (s *scheme) UnmarshalTextPrivateKey(text []byte) (kem.PrivateKey, error) {
	return pem.FromPrivatePEMBytes(text, s)
}

// public key methods

func (pk *PublicKey) Scheme() kem.Scheme {
	return pk.scheme
}

// EncapsulateTo generates a shared key and ciphertext that contains it
// for the public key using randomness from seed and writes the shared key
// to ss and ciphertext to ct.
//
// Panics if ss, ct or seed are not of length SharedKeySize, CiphertextSize
// and EncapsulationSeedSize respectively.
//
// seed may be nil, in which case hpqc/rand.Reader is used to generate one.
func (pk *PublicKey) EncapsulateTo(ct, ss []byte, seed []byte) {
	if seed == nil {
		seed = make([]byte, EncapsulationSeedSize)
		if _, err := rand.Reader.Read(seed[:]); err != nil {
			panic(err)
		}
	} else {
		if len(seed) != EncapsulationSeedSize {
			panic("seed must be of length EncapsulationSeedSize")
		}
	}

	if len(ct) != CiphertextSize {
		panic("ct must be of length CiphertextSize")
	}

	if len(ss) != SharedKeySize {
		panic("ss must be of length SharedKeySize")
	}

	ciphertext, sharedkey, err := sntrup.Encapsulate(newKDF(seed, kdfEncapInfo), pk.key)
	if err != nil {
		panic(err)
	}

	copy(ct, ciphertext[:])
	copy(ss, sharedkey[:])
}

func (pk *PublicKey) MarshalBinary() (data []byte, err error) {
	return pk.key[:], nil
}

func (pk *PublicKey) MarshalText() (text []byte, err error) {
	return pem.ToPublicPEMBytes(pk), nil
}

func (pk *PublicKey) Equal(other kem.PublicKey) bool {
	oth, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	if pk.key == nil || oth.key == nil {
		panic("keys cannot be nil")
	}
	return hmac.Equal(pk.key[:], oth.key[:])
}

// private key methods

func (sk *PrivateKey) Scheme() kem.Scheme {
	return sk.scheme
}

func (sk *PrivateKey) Public() kem.PublicKey {
	pubkey, _, err := Scheme().GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	pk := pubkey.(*PublicKey)
	copy(pk.key[:], sk.key[382:])
	return pk
}

// DecapsulateTo computes the shared key which is encapsulated in ct
// for the private key.
//
// Panics if ct or ss are not of length CiphertextSize and SharedKeySize
// respectively.
func (sk *PrivateKey) DecapsulateTo(ss, ct []byte) {
	if len(ct) != CiphertextSize {
		panic("ct must be of length CiphertextSize")
	}

	if len(ss) != SharedKeySize {
		panic("ss must be of length SharedKeySize")
	}

	ciphertext := new(sntrup.Ciphertext)
	copy(ciphertext[:], ct)
	sharedkey, ok := sntrup.Decapsulate(ciphertext, sk.key)
	if ok != 1 {
		panic("sntrup.Decapsulate failed")
	}
	copy(ss, sharedkey[:])
}

func (sk *PrivateKey) MarshalBinary() (data []byte, err error) {
	return sk.key[:], nil
}

func (sk *PrivateKey) Equal(other kem.PrivateKey) bool {
	oth, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	if sk.key == nil || oth.key == nil {
		panic("keys cannot be nil")
	}
	return hmac.Equal(sk.key[:], oth.key[:])
}
