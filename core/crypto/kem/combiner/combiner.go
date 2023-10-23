// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package combiner defines a KEM combiner type that can combine any number of KEMs.
// The KEM combiner is described here: https://eprint.iacr.org/2018/024.pdf
package combiner

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/katzenpost/katzenpost/core/crypto/kem/utils"
)

var (
	// ErrUninitialized indicates a key wasn't initialized.
	ErrUninitialized = errors.New("public or private key not initialized")
)

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
	for _, s := range sch.schemes {
		sum += s.PublicKeySize()
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
	sum := 0
	for _, s := range sch.schemes {
		sum += s.SharedKeySize()
	}
	return sum
}

// CiphertextSize returns the KEM's ciphertext size in bytes.
func (sch *Scheme) CiphertextSize() int {
	sum := 0
	for _, s := range sch.schemes {
		sum += s.CiphertextSize()
	}
	return sum
}

// EncapsulationSeedSize returns the KEM's encapsulation seed size in bytes.
func (sch *Scheme) EncapsulationSeedSize() int {
	sum := 0
	for _, s := range sch.schemes {
		sum += s.EncapsulationSeedSize()
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
	seed := make([]byte, sch.EncapsulationSeedSize())
	_, err = rand.Reader.Read(seed)
	if err != nil {
		return
	}
	return sch.EncapsulateDeterministically(pk, seed)
}

// EncapsulateDeterministically deterministircally encapsulates a share secret to the given public key and the given seed value.
func (sch *Scheme) EncapsulateDeterministically(publicKey kem.PublicKey, seed []byte) (ct, ss []byte, err error) {
	if len(seed) != sch.EncapsulationSeedSize() {
		return nil, nil, kem.ErrSeedSize
	}

	seeds := make([][]byte, len(sch.schemes))
	offset := sch.schemes[0].EncapsulationSeedSize()
	seeds[0] = seed[:offset]

	for i := 1; i < len(sch.schemes); i++ {
		seedSize := sch.schemes[i].EncapsulationSeedSize()
		seeds[i] = seed[offset : offset+seedSize]
		offset += seedSize
	}

	pub, ok := publicKey.(*PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}

	ciphertexts := make([][]byte, len(sch.schemes))
	sharedSecrets := make([][]byte, len(sch.schemes))
	ciphertextBlob := []byte{}

	for i := 0; i < len(sch.schemes); i++ {
		cct, ss, err := sch.schemes[i].EncapsulateDeterministically(pub.keys[i], seeds[i])
		if err != nil {
			return nil, nil, err
		}
		ciphertexts[i] = cct
		sharedSecrets[i] = ss
		ciphertextBlob = append(ciphertextBlob, cct...)
	}

	ss = utils.SplitPRF(sharedSecrets, ciphertexts)

	return ciphertextBlob, ss, nil
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

	return utils.SplitPRF(sharedSecrets, ciphertexts), nil
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
	for i := 0; i < len(sch.schemes); i++ {
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
	offset := sch.schemes[0].PrivateKeySize()
	pk1, err := sch.schemes[0].UnmarshalBinaryPrivateKey(buf[:offset])
	if err != nil {
		return nil, err
	}
	privateKeys[0] = pk1
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
