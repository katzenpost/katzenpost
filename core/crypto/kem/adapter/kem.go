package adapter

import (
	"crypto/hmac"
	"fmt"

	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

const (
	// SeedSize is the number of bytes needed to seed deterministic methods below.
	SeedSize = 32
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

func hashSharedSecretWithPublicKeys(publicKeySize int, ss []byte, pubkey1 []byte, pubkey2 []byte) []byte {
	var h blake2b.XOF
	var err error
	if len(ss) != 32 {
		sum := blake2b.Sum256(ss)
		h, err = blake2b.NewXOF(uint32(publicKeySize), sum[:])
	} else {
		h, err = blake2b.NewXOF(uint32(publicKeySize), ss)
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
func (a *Scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	if len(ct) != a.CiphertextSize() {
		return nil, kem.ErrCiphertextSize
	}
	pk, err := a.UnmarshalBinaryPublicKey(ct)
	if err != nil {
		return nil, err
	}
	ss := a.nike.DeriveSecret(sk.(*PrivateKey).privateKey, pk.(*PublicKey).publicKey)
	ss2 := hashSharedSecretWithPublicKeys(a.nike.PublicKeySize(), ss, sk.Public().(*PublicKey).publicKey.Bytes(), pk.(*PublicKey).publicKey.Bytes())
	return ss2, nil
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
		panic(fmt.Errorf("%s: provided seed of length %d is != to correct seed size of %d", kem.ErrSeedSize, len(seed), a.SeedSize()))
	}
	h, err := blake2b.NewXOF(0, nil)
	if err != nil {
		panic(err)
	}

	seedHash := blake2b.Sum256(seed)
	_, _ = h.Write(seedHash[:])
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
	[]byte, []byte, error) {
	if len(seed) != a.EncapsulationSeedSize() {
		return nil, nil, kem.ErrSeedSize
	}
	pub, ok := pk.(*PublicKey)
	if !ok || pub.scheme != a {
		return nil, nil, kem.ErrTypeMismatch
	}

	pk2, sk2 := a.DeriveKeyPair(seed)

	// ss = DH(my_priv_key, their_pub_key)
	ss := a.nike.DeriveSecret(sk2.(*PrivateKey).privateKey, pub.publicKey)

	// ss2 = H(ss || my_pubkey || their_pubkey)
	ss2 := hashSharedSecretWithPublicKeys(a.nike.PublicKeySize(), ss, pk2.(*PublicKey).publicKey.Bytes(), pub.publicKey.Bytes())
	ct, _ := pk2.MarshalBinary()
	return ct, ss2, nil
}

// Size of seed used in EncapsulateDeterministically().
func (a *Scheme) EncapsulationSeedSize() int {
	return SeedSize
}
