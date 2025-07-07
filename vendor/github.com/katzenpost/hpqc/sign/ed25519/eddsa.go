// SPDX-FileCopyrightText: (c) 2023 David Stainton and Yawning Angel
// SPDX-License-Identifier: AGPL-3.0-only

// Package is our ed25519 wrapper type which also conforms to our generic interfaces for signature schemes.
package ed25519

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/blake2b"

	"filippo.io/edwards25519"

	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/pem"
	"github.com/katzenpost/hpqc/util"
)

const (
	// PublicKeySize is the size of a serialized PublicKey in bytes (32 bytes).
	PublicKeySize = ed25519.PublicKeySize

	// PrivateKeySize is the size of a serialized PrivateKey in bytes (64 bytes).
	PrivateKeySize = ed25519.PrivateKeySize

	// SignatureSize is the size of a serialized Signature in bytes (64 bytes).
	SignatureSize = ed25519.SignatureSize

	// KeySeedSize is the seed size used by NewKeyFromSeed to generate
	// a new key deterministically.
	KeySeedSize = 32

	keyType = "ed25519"
)

var errInvalidKey = errors.New("eddsa: invalid key")

// Scheme implements our sign.Scheme interface using the ed25519 wrapper.
type scheme struct{}

var sch *scheme = &scheme{}

// Scheme returns a sign Scheme interface.
func Scheme() *scheme { return sch }

func (s *scheme) Name() string {
	return "Ed25519"
}

func (s *scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	privKey, _, err := NewKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}

	return privKey.PublicKey(), privKey, nil
}

func (s *scheme) Sign(sk sign.PrivateKey, message []byte, opts *sign.SignatureOpts) []byte {
	sig, err := sk.Sign(nil, message, nil)
	if err != nil {
		panic(err)
	}
	return sig
}

func (s *scheme) Verify(pk sign.PublicKey, message []byte, signature []byte, opts *sign.SignatureOpts) bool {
	return ed25519.Verify(pk.(*PublicKey).pubKey, message, signature)
}

func (s *scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	return NewKeyFromSeed(seed)
}

func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	pubKey := new(PublicKey)
	err := pubKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	privKey := new(PrivateKey)
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func (s *scheme) PublicKeySize() int {
	return PublicKeySize
}

func (s *scheme) PrivateKeySize() int {
	return PrivateKeySize
}

func (s *scheme) SignatureSize() int {
	return SignatureSize
}

func (s *scheme) SeedSize() int {
	return KeySeedSize
}

func (s *scheme) SupportsContext() bool {
	return false
}

type PrivateKey struct {
	pubKey  PublicKey
	privKey ed25519.PrivateKey
}

func NewEmptyPrivateKey() *PrivateKey {
	return &PrivateKey{
		privKey: make([]byte, PrivateKeySize),
	}
}

func (p *PrivateKey) Scheme() sign.Scheme {
	return Scheme()
}

func (p *PrivateKey) Equal(key crypto.PrivateKey) bool {
	return hmac.Equal(p.Bytes(), key.(*PrivateKey).Bytes())
}

func (p *PrivateKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *PrivateKey) UnmarshalBinary(b []byte) error {
	return p.FromBytes(b)
}

// signer interface methods

func (p *PrivateKey) Public() crypto.PublicKey {
	return p.PublicKey()
}

func (p *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	sig := p.SignMessage(digest)
	return sig, nil
}

// InternalPtr returns a pointer to the internal (`golang.org/x/crypto/ed25519`)
// data structure.  Most people should not use this.
func (p *PrivateKey) InternalPtr() *ed25519.PrivateKey {
	return &p.privKey
}

func (p *PrivateKey) KeyType() string {
	return "ED25519 PRIVATE KEY"
}

func (p *PrivateKey) SignMessage(message []byte) (signature []byte) {
	return ed25519.Sign(p.privKey, message)
}

func (p *PrivateKey) Reset() {
	p.pubKey.Reset()
	util.ExplicitBzero(p.privKey)
}

func (p *PrivateKey) Bytes() []byte {
	return p.privKey
}

// FromBytes deserializes the byte slice b into the PrivateKey.
func (p *PrivateKey) FromBytes(b []byte) error {
	if len(b) != PrivateKeySize {
		return errInvalidKey
	}

	p.privKey = make([]byte, PrivateKeySize)
	copy(p.privKey, b)
	p.pubKey.pubKey = p.privKey.Public().(ed25519.PublicKey)
	p.pubKey.rebuildB64String()
	return nil
}

// Identity returns the key's identity, in this case it's our
// public key in bytes.
func (p *PrivateKey) Identity() []byte {
	return p.PublicKey().Bytes()
}

// PublicKey returns the PublicKey corresponding to the PrivateKey.
func (p *PrivateKey) PublicKey() *PublicKey {
	return &p.pubKey
}

// PublicKey is the EdDSA public key using ed25519.
type PublicKey struct {
	pubKey    ed25519.PublicKey
	b64String string
}

func (p *PublicKey) Scheme() sign.Scheme {
	return Scheme()
}

func (p *PublicKey) Equal(pubKey crypto.PublicKey) bool {
	return hmac.Equal(p.pubKey[:], pubKey.(*PublicKey).pubKey[:])
}

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

// ToECDH converts the PublicKey to the corresponding ecdh.PublicKey.
func (p *PublicKey) ToECDH() *x25519.PublicKey {
	ed_pub, _ := new(edwards25519.Point).SetBytes(p.Bytes())
	r := new(x25519.PublicKey)
	if r.FromBytes(ed_pub.BytesMontgomery()) != nil {
		panic("edwards.Point from pub.BytesMontgomery failed, impossible. ")
	}
	return r
}

// InternalPtr returns a pointer to the internal (`golang.org/x/crypto/ed25519`)
// data structure.  Most people should not use this.
func (k *PublicKey) InternalPtr() *ed25519.PublicKey {
	return &k.pubKey
}

func (p *PublicKey) KeyType() string {
	return "ED25519 PUBLIC KEY"
}

func (p *PublicKey) Sum256() [32]byte {
	return blake2b.Sum256(p.Bytes())
}

func (p *PublicKey) Verify(signature, message []byte) bool {
	return ed25519.Verify(p.pubKey, message, signature)
}

func (p *PublicKey) Reset() {
	util.ExplicitBzero(p.pubKey)
	p.b64String = "[scrubbed]"
}

func (p *PublicKey) Bytes() []byte {
	return p.pubKey
}

// ByteArray returns the raw public key as an array suitable for use as a map
// key.
func (p *PublicKey) ByteArray() [PublicKeySize]byte {
	var pk [PublicKeySize]byte
	copy(pk[:], p.pubKey[:])
	return pk
}

func (p *PublicKey) rebuildB64String() {
	p.b64String = base64.StdEncoding.EncodeToString(p.Bytes())
}

func (p *PublicKey) FromBytes(data []byte) error {
	if len(data) != PublicKeySize {
		return errInvalidKey
	}

	p.pubKey = make([]byte, PublicKeySize)
	copy(p.pubKey, data)
	p.rebuildB64String()
	return nil
}

func (p *PublicKey) UnmarshalBinary(data []byte) error {
	return p.FromBytes(data)
}

func (p *PublicKey) MarshalText() (text []byte, err error) {
	return pem.ToPublicPEMBytes(p), nil
}

func (p *PublicKey) UnmarshalText(text []byte) error {
	pubkey, err := pem.FromPublicPEMString(string(text), p.Scheme())
	if err != nil {
		return err
	}
	p = pubkey.(*PublicKey)
	return nil
}

// NewKeypair generates a new PrivateKey sampled from the provided entropy
// source.
func NewKeypair(r io.Reader) (*PrivateKey, *PublicKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, nil, err
	}

	k := new(PrivateKey)
	k.privKey = privKey
	k.pubKey.pubKey = pubKey
	k.pubKey.rebuildB64String()
	return k, k.PublicKey(), nil
}

func NewKeyFromSeed(seed []byte) (*PublicKey, *PrivateKey) {
	if len(seed) != KeySeedSize {
		panic("seed must be of length KeySeedSize")
	}
	xof, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, seed)
	if err != nil {
		panic(err)
	}
	privkey, pubkey, err := NewKeypair(xof)
	if err != nil {
		panic(err)
	}
	return pubkey, privkey
}
