// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package combiner defines a security preserving KEM combiner.
// The [KEM Combiners paper](https://eprint.iacr.org/2018/024.pdf) makes the
// observation that if a KEM combiner is not security preserving then the
// resulting hybrid KEM will not have IND-CCA2 security if one of the
// composing KEMs does not have IND-CCA2 security. Likewise the paper
// points out that when using a security preserving KEM combiner, if only
// one of the composing KEMs has IND-CCA2 security then the resulting
// hybrid KEM will have IND-CCA2 security.
//
// Our KEM combiner uses the split PRF design for an arbitrary number
// of kems, here shown with only three, in pseudo code:
//
// ```
//
//	func SplitPRF(ss1, ss2, ss3, cct1, cct2, cct3 []byte) []byte {
//	    cct := cct1 || cct2 || cct3
//	    return PRF(ss1 || cct) XOR PRF(ss2 || cct) XOR PRF(ss3 || cct)
//	}
//
// ```
package combiner

import (
	"errors"
	"fmt"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/util"
	"golang.org/x/crypto/blake2b"
)

var (
	// ErrUninitialized indicates a key wasn't initialized.
	ErrUninitialized = errors.New("public or private key not initialized")
)

var _ kem.PrivateKey = (*PrivateKey)(nil)
var _ kem.PublicKey = (*PublicKey)(nil)
var _ kem.Scheme = (*Scheme)(nil)

// Public key of a combined KEMs.
type PublicKey struct {
	scheme *Scheme
	keys   []kem.PublicKey
}

// Private key of a hybrid KEM.
type PrivateKey struct {
	scheme *Scheme
	keys   []kem.PrivateKey
}

// Scheme for a hybrid KEM.
type Scheme struct {
	name    string
	schemes []kem.Scheme
}

// PrivateKey methods

// Scheme returns the given private key's scheme object.
func (sk *PrivateKey) Scheme() kem.Scheme { return sk.scheme }

// MarshalBinary creates a binary blob of the key.
func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	if sk.keys == nil {
		return nil, ErrUninitialized
	}
	for _, s := range sk.keys {
		if s == nil {
			return nil, ErrUninitialized
		}
	}

	blobs := []byte{}
	for i := 0; i < len(sk.keys); i++ {
		blob, err := sk.keys[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		blobs = append(blobs, blob...)
	}

	return blobs, nil
}

// Equal performs a non-constant time key comparison.
func (sk *PrivateKey) Equal(other kem.PrivateKey) bool {
	oth, ok := other.(*PrivateKey)
	if !ok {
		return false
	}

	for i := 0; i < len(sk.keys); i++ {
		if !sk.keys[i].Equal(oth.keys[i]) {
			return false
		}
	}
	return true
}

// Public returns a public key, given a private key.
func (sk *PrivateKey) Public() kem.PublicKey {
	pubkeys := make([]kem.PublicKey, len(sk.keys))
	for i := 0; i < len(sk.keys); i++ {
		pubkeys[i] = sk.keys[i].Public()
	}
	return &PublicKey{
		scheme: sk.scheme,
		keys:   pubkeys,
	}
}

// PublicKey methods

// Scheme returns the scheme object for the given public key.
func (pk *PublicKey) Scheme() kem.Scheme { return pk.scheme }

// Equal performs a non-constant time key comparison.
func (sk *PublicKey) Equal(other kem.PublicKey) bool {
	oth, ok := other.(*PublicKey)
	if !ok {
		return false
	}

	for i := 0; i < len(sk.keys); i++ {
		if !sk.keys[i].Equal(oth.keys[i]) {
			return false
		}
	}
	return true
}

// MarshalBinary returns a binary blob of the key.
func (sk *PublicKey) MarshalBinary() ([]byte, error) {
	if sk.keys == nil {
		return nil, ErrUninitialized
	}
	for _, s := range sk.keys {
		if s == nil {
			return nil, ErrUninitialized
		}
	}

	blobs := []byte{}
	for i := 0; i < len(sk.keys); i++ {
		blob, err := sk.keys[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		blobs = append(blobs, blob...)
	}

	return blobs, nil
}

func (sk *PublicKey) MarshalText() (text []byte, err error) {
	return pem.ToPublicPEMBytes(sk), nil
}

// Scheme methods

// New creates a new hybrid KEM given the slices of KEM schemes.
func New(name string, schemes []kem.Scheme) *Scheme {
	for _, x := range schemes {
		if x == nil {
			panic("KEM scheme cannot be nil")
		}
	}
	return &Scheme{
		name:    name,
		schemes: schemes,
	}
}

// Name returns the name of the KEM.
func (sch *Scheme) Name() string { return sch.name }

// PublicKeySize returns the KEM's public key size in bytes.
func (sch *Scheme) PublicKeySize() int {
	sum := 0
	for i := 0; i < len(sch.schemes); i++ {
		sum += sch.schemes[i].PublicKeySize()
	}
	return sum
}

// PrivateKeySize returns the KEM's private key size in bytes.
func (sch *Scheme) PrivateKeySize() int {
	sum := 0
	for _, s := range sch.schemes {
		sum += s.PrivateKeySize()
	}
	return sum
}

// SeedSize returns the KEM's seed size in bytes.
func (sch *Scheme) SeedSize() int {
	sum := 0
	for _, s := range sch.schemes {
		sum += s.SeedSize()
	}
	return sum
}

// SharedKeySize returns the KEM's shared key size in bytes.
func (sch *Scheme) SharedKeySize() int {
	return blake2b.Size256
}

// CiphertextSize returns the KEM's ciphertext size in bytes.
func (sch *Scheme) CiphertextSize() int {
	sum := 0
	for _, s := range sch.schemes {
		sum += s.CiphertextSize()
	}
	return sum
}

// GenerateKeyPair generates a keypair.
func (sch *Scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	pubKeys := make([]kem.PublicKey, len(sch.schemes))
	privKeys := make([]kem.PrivateKey, len(sch.schemes))

	for i := 0; i < len(sch.schemes); i++ {
		pk, sk, err := sch.schemes[i].GenerateKeyPair()
		if err != nil {
			return nil, nil, err
		}
		pubKeys[i] = pk
		privKeys[i] = sk
	}

	return &PublicKey{
			scheme: sch,
			keys:   pubKeys,
		}, &PrivateKey{
			scheme: sch,
			keys:   privKeys,
		}, nil
}

// DeriveKeyPair uses a seed value to deterministically generate a key pair.
func (sch *Scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != sch.SeedSize() {
		panic(fmt.Sprintf("seed size must be %d", sch.SeedSize()))
	}

	pubKeys := make([]kem.PublicKey, len(sch.schemes))
	privKeys := make([]kem.PrivateKey, len(sch.schemes))

	offset := sch.schemes[0].SeedSize()
	pubKeys[0], privKeys[0] = sch.schemes[0].DeriveKeyPair(seed[:offset])

	for i := 1; i < len(sch.schemes); i++ {
		seedSize := sch.schemes[i].SeedSize()
		pubKeys[i], privKeys[i] = sch.schemes[i].DeriveKeyPair(seed[offset : offset+seedSize])
		offset += seedSize
	}

	return &PublicKey{
			scheme: sch,
			keys:   pubKeys,
		}, &PrivateKey{
			scheme: sch,
			keys:   privKeys,
		}
}

// Encapsulate creates a shared secret and ciphertext given a public key.
func (sch *Scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	pub, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}

	ciphertexts := make([][]byte, len(sch.schemes))
	sharedSecrets := make([][]byte, len(sch.schemes))
	ciphertextBlob := []byte{}

	for i := 0; i < len(sch.schemes); i++ {
		cct, ss, err := sch.schemes[i].Encapsulate(pub.keys[i])
		if err != nil {
			return nil, nil, err
		}
		ciphertexts[i] = cct
		sharedSecrets[i] = ss
		ciphertextBlob = append(ciphertextBlob, cct...)
	}

	ss = util.SplitPRF(sharedSecrets, ciphertexts)

	return ciphertextBlob, ss, nil
}

// EncapsulateDeterministically deterministircally encapsulates a share secret to the given public key and the given seed value.
func (sch *Scheme) EncapsulateDeterministically(publicKey kem.PublicKey, seed []byte) (ct, ss []byte, err error) {
	panic("not implemented")
}

// Decapsulate decrypts a given KEM ciphertext using the given private key.
func (sch *Scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	if len(ct) != sch.CiphertextSize() {
		return nil, kem.ErrCiphertextSize
	}

	priv, ok := sk.(*PrivateKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}

	sharedSecrets := make([][]byte, len(sch.schemes))
	ciphertexts := make([][]byte, len(sch.schemes))
	offset := sch.schemes[0].CiphertextSize()

	ss, err := sch.schemes[0].Decapsulate(priv.keys[0], ct[:offset])
	if err != nil {
		return nil, err
	}

	sharedSecrets[0] = ss
	ciphertexts[0] = ct[:offset]

	for i := 1; i < len(sch.schemes); i++ {
		ciphertextSize := sch.schemes[i].CiphertextSize()
		ciphertexts[i] = ct[offset : offset+ciphertextSize]
		sharedSecrets[i], err = sch.schemes[i].Decapsulate(priv.keys[i], ciphertexts[i])
		if err != nil {
			return nil, err
		}
		offset += ciphertextSize
	}

	return util.SplitPRF(sharedSecrets, ciphertexts), nil
}

// UnmarshalBinaryPublicKey unmarshals a binary blob representing a public key.
func (sch *Scheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
	if len(buf) != sch.PublicKeySize() {
		return nil, kem.ErrPubKeySize
	}
	publicKeys := make([]kem.PublicKey, len(sch.schemes))
	offset := sch.schemes[0].PublicKeySize()
	pk1, err := sch.schemes[0].UnmarshalBinaryPublicKey(buf[:offset])
	if err != nil {
		return nil, err
	}
	publicKeys[0] = pk1
	for i := 1; i < len(sch.schemes); i++ {
		pk, err := sch.schemes[i].UnmarshalBinaryPublicKey(buf[offset : offset+sch.schemes[i].PublicKeySize()])
		if err != nil {
			return nil, err
		}
		publicKeys[i] = pk
		offset += sch.schemes[i].PublicKeySize()
	}
	return &PublicKey{
		scheme: sch,
		keys:   publicKeys,
	}, nil
}

// UnmarshalBinaryPrivateKey unmarshals a binary blob representing a private key.
func (sch *Scheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
	if len(buf) != sch.PrivateKeySize() {
		return nil, kem.ErrPubKeySize
	}
	privateKeys := make([]kem.PrivateKey, len(sch.schemes))
	offset := 0
	for i := 0; i < len(sch.schemes); i++ {
		pk, err := sch.schemes[i].UnmarshalBinaryPrivateKey(buf[offset : offset+sch.schemes[i].PrivateKeySize()])
		if err != nil {
			return nil, err
		}
		privateKeys[i] = pk
		offset += sch.schemes[i].PrivateKeySize()
	}
	return &PrivateKey{
		scheme: sch,
		keys:   privateKeys,
	}, nil
}

func (sch *Scheme) UnmarshalTextPublicKey(text []byte) (kem.PublicKey, error) {
	return pem.FromPublicPEMBytes(text, sch)
}

func (sch *Scheme) UnmarshalTextPrivateKey(text []byte) (kem.PrivateKey, error) {
	return pem.FromPrivatePEMBytes(text, sch)
}
