package adapter

import (
	"crypto/hmac"
	"golang.org/x/crypto/sha3"

	"github.com/cloudflare/circl/kem"
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

// PublicKey is an adapter for nike.PublicKey to kem.PublicKey.
type PublicKey struct {
	publicKey nike.PublicKey
	scheme    *Scheme
}

func (p *PublicKey) Scheme() kem.Scheme {
	return p.scheme
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
type Scheme struct {
	nike nike.Scheme
}

var _ kem.Scheme = (*Scheme)(nil)
var _ kem.PublicKey = (*PublicKey)(nil)
var _ kem.PrivateKey = (*PrivateKey)(nil)

// FromNIKE creates a new KEM adapter Scheme
// using the given NIKE Scheme.
func FromNIKE(nike nike.Scheme) *Scheme {
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
	seed := make([]byte, a.EncapsulationSeedSize())
	_, err = rand.Reader.Read(seed)
	if err != nil {
		return
	}
	return a.EncapsulateDeterministically(pk, seed)
}

// Returns the shared key encapsulated in ciphertext ct for the
// private key sk.
func (a *Scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	if len(ct) != a.CiphertextSize() {
		return nil, kem.ErrCiphertextSize
	}
	pk, err := a.UnmarshalBinaryPublicKey(ct)
	if err != nil {
		return nil, err
	}
	ss := a.nike.DeriveSecret(sk.(*PrivateKey).privateKey, pk.(*PublicKey).publicKey)
	return ss, nil
}

// Unmarshals a PublicKey from the provided buffer.
func (a *Scheme) UnmarshalBinaryPublicKey(b []byte) (kem.PublicKey, error) {
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
	privkey, err := a.nike.UnmarshalBinaryPrivateKey(b)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		privateKey: privkey,
		scheme:     a,
	}, nil
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

// DeriveKeyPair deterministicallly derives a pair of keys from a seed.
// Panics if the length of seed is not equal to the value returned by
// SeedSize.
func (a *Scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != a.SeedSize() {
		panic(kem.ErrSeedSize)
	}
	h := sha3.NewShake256()
	_, _ = h.Write(seed)
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
	return a.nike.PublicKeySize()
}

// EncapsulateDeterministically generates a shared key ss for the public
// key deterministically from the given seed and encapsulates it into
// a ciphertext ct. If unsure, you're better off using Encapsulate().
func (a *Scheme) EncapsulateDeterministically(pk kem.PublicKey, seed []byte) (
	ct, ss []byte, err error) {
	if len(seed) != a.EncapsulationSeedSize() {
		return nil, nil, kem.ErrSeedSize
	}
	pub, ok := pk.(*PublicKey)
	if !ok || pub.scheme != a {
		return nil, nil, kem.ErrTypeMismatch
	}

	pk2, sk2 := a.DeriveKeyPair(seed)
	ss = a.nike.DeriveSecret(sk2.(*PrivateKey).privateKey, pub.publicKey)
	ct, _ = pk2.MarshalBinary()
	return ct, ss, nil
}

// Size of seed used in EncapsulateDeterministically().
func (a *Scheme) EncapsulationSeedSize() int {
	return a.nike.PublicKeySize()
}
