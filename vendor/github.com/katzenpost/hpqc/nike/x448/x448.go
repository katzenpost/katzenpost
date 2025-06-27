// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package x448

import (
	"encoding/base64"
	"errors"
	"io"

	"github.com/katzenpost/circl/dh/x448"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/util"
)

const (
	// GroupElementLength is the length of a ECDH group element in bytes.
	GroupElementLength = 56

	// PublicKeySize is the size of a serialized PublicKey in bytes.
	PublicKeySize = GroupElementLength

	// PrivateKeySize is the size of a serialized PrivateKey in bytes.
	PrivateKeySize = GroupElementLength
)

var (
	// ErrBlindDataSizeInvalid indicates that the blinding data size was invalid.
	ErrBlindDataSizeInvalid error = errors.New("x448: blinding data size invalid")

	errInvalidKey = errors.New("x448: invalid key")
)

var _ nike.PrivateKey = (*PrivateKey)(nil)
var _ nike.PublicKey = (*PublicKey)(nil)
var _ nike.Scheme = (*scheme)(nil)

// EcdhNike implements the Nike interface using our ecdh module.
type scheme struct {
	rng io.Reader
}

// Scheme instantiates a new X448 scheme given a CSPRNG.
func Scheme(rng io.Reader) *scheme {
	return &scheme{
		rng: rng,
	}
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
	return "x448"
}

// PublicKeySize returns the size in bytes of the public key.
func (e *scheme) PublicKeySize() int {
	return PublicKeySize
}

// PrivateKeySize returns the size in bytes of the private key.
func (e *scheme) PrivateKeySize() int {
	return PublicKeySize
}

// NewEmptyPublicKey returns an uninitialized
// PublicKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func (e *scheme) NewEmptyPublicKey() nike.PublicKey {
	return &PublicKey{
		pubBytes: new(x448.Key),
	}
}

// NewEmptyPrivateKey returns an uninitialized
// PrivateKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func (e *scheme) NewEmptyPrivateKey() nike.PrivateKey {
	return &PrivateKey{
		privBytes: new(x448.Key),
	}
}

// DeriveSecret derives a shared secret given a private key
// from one party and a public key from another.
func (e *scheme) DeriveSecret(privKey nike.PrivateKey, pubKey nike.PublicKey) []byte {
	sharedSecret := Exp(privKey.(*PrivateKey).privBytes, (pubKey.(*PublicKey)).pubBytes)
	return sharedSecret[:]
}

// DerivePublicKey derives a public key given a private key.
func (e *scheme) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	return privKey.(*PrivateKey).Public()
}

func (e *scheme) Blind(groupMember nike.PublicKey, blindingFactor nike.PrivateKey) nike.PublicKey {
	sharedSecret := Exp(blindingFactor.(*PrivateKey).privBytes, groupMember.(*PublicKey).pubBytes)
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

type PrivateKey struct {
	privBytes *x448.Key
}

func NewKeypair(rng io.Reader) (nike.PrivateKey, error) {
	privkey := new(x448.Key)
	count, err := rng.Read(privkey[:])
	if err != nil {
		return nil, err
	}
	if count != GroupElementLength {
		return nil, errors.New("read wrong number of bytes from rng")
	}
	return &PrivateKey{
		privBytes: privkey,
	}, nil
}

func (p *PrivateKey) Public() nike.PublicKey {
	pubKey := Scheme(rand.Reader).NewEmptyPublicKey()
	expG(pubKey.(*PublicKey).pubBytes, p.privBytes)
	return pubKey
}

func (p *PrivateKey) Reset() {
	zeros := make([]byte, PrivateKeySize)
	err := p.FromBytes(zeros)
	if err != nil {
		panic(err)
	}
}

func (p *PrivateKey) Bytes() []byte {
	b := make([]byte, PublicKeySize)
	copy(b, p.privBytes[:])
	return b
}

func (p *PrivateKey) FromBytes(data []byte) error {
	if len(data) != PrivateKeySize {
		return errInvalidKey
	}

	p.privBytes = new(x448.Key)
	copy(p.privBytes[:], data)

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

type PublicKey struct {
	pubBytes *x448.Key
}

func (p *PublicKey) Blind(blindingFactor nike.PrivateKey) error {
	_, ok := blindingFactor.(*PrivateKey)
	if !ok {
		return errors.New("blindingFactor nike.PrivateKey must be the same concrete type as x448.PublicKey")
	}
	pubBytes := Exp(blindingFactor.(*PrivateKey).privBytes, p.pubBytes)
	copy(p.pubBytes[:], pubBytes)
	util.ExplicitBzero(pubBytes)
	return nil
}

func (p *PublicKey) Reset() {
	zeros := make([]byte, PublicKeySize)
	err := p.FromBytes(zeros)
	if err != nil {
		panic(err)
	}
}

func (p *PublicKey) Bytes() []byte {
	b := make([]byte, PublicKeySize)
	copy(b, p.pubBytes[:])
	return b
}

func (p *PublicKey) FromBytes(data []byte) error {
	if len(data) != PublicKeySize {
		return errInvalidKey
	}

	p.pubBytes = new(x448.Key)
	copy(p.pubBytes[:], data)

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

// Exp returns the group element, the result of x^y, over the ECDH group.
func Exp(x, y *x448.Key) []byte {
	sharedSecret := new(x448.Key)
	ok := x448.Shared(sharedSecret, x, y)
	if !ok {
		panic("x448.Shared failed")
	}
	return sharedSecret[:]
}

func expG(dst, y *x448.Key) {
	x448.KeyGen(dst, y)
}
