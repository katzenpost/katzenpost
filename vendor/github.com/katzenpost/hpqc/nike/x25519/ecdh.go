// SPDX-FileCopyrightText: © 2023 David Stainton and Yawning Angel
// SPDX-License-Identifier: AGPL-3.0-only

package x25519

import (
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/util"
)

const (
	// GroupElementLength is the length of a ECDH group element in bytes.
	GroupElementLength = 32

	// PublicKeySize is the size of a serialized PublicKey in bytes.
	PublicKeySize = GroupElementLength

	// PrivateKeySize is the size of a serialized PrivateKey in bytes.
	PrivateKeySize = GroupElementLength
)

var (
	// ErrBlindDataSizeInvalid indicates that the blinding data size was invalid.
	ErrBlindDataSizeInvalid error = errors.New("ecdh: blinding data size invalid")

	errInvalidKey = errors.New("ecdh: invalid key")
)

var _ nike.PrivateKey = (*PrivateKey)(nil)
var _ nike.PublicKey = (*PublicKey)(nil)
var _ nike.Scheme = (*scheme)(nil)

// EcdhNike implements the Nike interface using our ecdh module.
type scheme struct {
	rng io.Reader
}

// Scheme instantiates a new X25519 scheme given a CSPRNG.
func Scheme(rng io.Reader) *scheme {
	return &scheme{
		rng: rng,
	}
}

type PrivateKey [GroupElementLength]byte

func (p *PrivateKey) Public() nike.PublicKey {
	return Scheme(rand.Reader).DerivePublicKey(p)
}

func (p *PrivateKey) Reset() {
	b := make([]byte, PrivateKeySize)
	err := p.FromBytes(b)
	if err != nil {
		panic(err)
	}
}

func (p *PrivateKey) Bytes() []byte {
	b := make([]byte, PrivateKeySize)
	copy(b, p[:])
	return b
}

func (p *PrivateKey) FromBytes(data []byte) error {
	if len(data) != PrivateKeySize {
		return errInvalidKey
	}

	copy(p[:], data)
	expG((*[GroupElementLength]byte)(p.Public().(*PublicKey)), (*[GroupElementLength]byte)(p))

	return nil
}

func (p *PrivateKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *PrivateKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(p.Bytes())), nil
}

func (p *PrivateKey) UnmarshalBinary(data []byte) error {
	return p.FromBytes(data)
}

func (p *PrivateKey) UnmarshalText(data []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}
	return p.FromBytes(raw)
}

// Exp calculates the shared secret with the provided public key.
func (k *PrivateKey) Exp(publicKey *PublicKey) []byte {
	return Exp(publicKey[:], k[:])
}

type PublicKey [GroupElementLength]byte

func (p *PublicKey) Blind(blindingFactor nike.PrivateKey) error {
	if len(blindingFactor.Bytes()) != GroupElementLength {
		return ErrBlindDataSizeInvalid
	}
	pubBytes := Exp(p[:], blindingFactor.Bytes())
	copy(p[:], pubBytes)
	util.ExplicitBzero(pubBytes)
	return nil
}

func (p *PublicKey) Reset() {
	util.ExplicitBzero(p[:])
}

func (p *PublicKey) Bytes() []byte {
	b := make([]byte, PublicKeySize)
	copy(b, p[:])
	return b
}

func (p *PublicKey) FromBytes(data []byte) error {
	if len(data) != PublicKeySize {
		return errInvalidKey
	}

	copy(p[:], data)

	return nil
}

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *PublicKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(p.Bytes())), nil
}

func (p *PublicKey) UnmarshalBinary(data []byte) error {
	return p.FromBytes(data)
}

func (p *PublicKey) UnmarshalText(data []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}
	return p.FromBytes(raw)
}

func (e *scheme) GeneratePrivateKey(rng io.Reader) nike.PrivateKey {
	privKey, err := NewKeypair(rng)
	if err != nil {
		panic(err)
	}
	return privKey
}

func (e *scheme) GenerateKeyPairFromEntropy(rng io.Reader) (nike.PublicKey, nike.PrivateKey, error) {
	privKey, err := NewKeypair(rng)
	if err != nil {
		return nil, nil, err
	}
	return privKey.Public(), privKey, nil
}

func (e *scheme) GenerateKeyPair() (nike.PublicKey, nike.PrivateKey, error) {
	return e.GenerateKeyPairFromEntropy(e.rng)
}

func (e *scheme) Name() string {
	return "x25519"
}

// PublicKeySize returns the size in bytes of the public key.
func (e *scheme) PublicKeySize() int {
	return PublicKeySize
}

// PrivateKeySize returns the size in bytes of the private key.
func (e *scheme) PrivateKeySize() int {
	return PrivateKeySize
}

// NewEmptyPublicKey returns an uninitialized
// PublicKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func (e *scheme) NewEmptyPublicKey() nike.PublicKey {
	return new(PublicKey)
}

// NewEmptyPrivateKey returns an uninitialized
// PrivateKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func (e *scheme) NewEmptyPrivateKey() nike.PrivateKey {
	return new(PrivateKey)
}

// DeriveSecret derives a shared secret given a private key
// from one party and a public key from another.
func (e *scheme) DeriveSecret(privKey nike.PrivateKey, pubKey nike.PublicKey) []byte {
	sharedSecret := privKey.(*PrivateKey).Exp(pubKey.(*PublicKey))
	return sharedSecret[:]
}

// DerivePublicKey derives a public key given a private key.
func (e *scheme) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	pubKey := e.NewEmptyPublicKey()
	expG((*[GroupElementLength]byte)(pubKey.(*PublicKey)), (*[GroupElementLength]byte)(privKey.(*PrivateKey)))
	return pubKey
}

func (e *scheme) Blind(groupMember nike.PublicKey, blindingFactor nike.PrivateKey) nike.PublicKey {
	sharedSecret := Exp(groupMember.Bytes(), blindingFactor.Bytes())
	pubKey := new(PublicKey)
	err := pubKey.FromBytes(sharedSecret)
	if err != nil {
		panic(err)
	}

	return pubKey
}

// UnmarshalBinaryPublicKey loads a public key from byte slice.
func (e *scheme) UnmarshalBinaryPublicKey(b []byte) (nike.PublicKey, error) {
	pubKey := new(PublicKey)
	err := pubKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// UnmarshalBinaryPrivateKey loads a private key from byte slice.
func (e *scheme) UnmarshalBinaryPrivateKey(b []byte) (nike.PrivateKey, error) {
	privKey := new(PrivateKey)
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, err
}

// Exp returns the group element, the result of x^y, over the ECDH group.
func Exp(x, y []byte) []byte {
	var err error
	if len(x) != GroupElementLength {
		panic(errInvalidKey)
	}
	if len(y) != GroupElementLength {
		panic(errInvalidKey)
	}
	sharedSecret, err := curve25519.X25519(y, x)
	if err != nil {
		panic(err)
	}
	return sharedSecret
}

func expG(dst, y *[GroupElementLength]byte) {
	curve25519.ScalarBaseMult(dst, y)
}

// NewKeypair generates a new PrivateKey sampled from the provided entropy
// source.
func NewKeypair(r io.Reader) (*PrivateKey, error) {
	k := new(PrivateKey)
	if _, err := io.ReadFull(r, k[:]); err != nil {
		return nil, err
	}

	expG((*[GroupElementLength]byte)(k.Public().(*PublicKey)), (*[GroupElementLength]byte)(k))

	return k, nil
}
