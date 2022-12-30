package hybrid

import (
	"github.com/katzenpost/katzenpost/core/crypto/nike"
)

// Public key of a hybrid NIKE.
type publicKey struct {
	scheme *scheme
	first  nike.PublicKey
	second nike.PublicKey
}

// Private key of a hybrid NIKE.
type privateKey struct {
	scheme *scheme
	first  nike.PrivateKey
	second nike.PrivateKey
}

// Scheme for a hybrid NIKE.
type scheme struct {
	name   string
	first  nike.Scheme
	second nike.Scheme
}

// PublicKeySize returns the size in bytes of the public key.
func (s *scheme) PublicKeySize() int {
	return s.first.PublicKeySize() + s.second.PublicKeySize()
}

// PrivateKeySize returns the size in bytes of the private key.
func (s *scheme) PrivateKeySize() int {
	return s.first.PrivateKeySize() + s.second.PrivateKeySize()
}

// NewKeypair returns a newly generated key pair.
func (s *scheme) NewKeypair() (nike.PrivateKey, nike.PublicKey) {
	privKey1, pubKey1 := s.first.NewKeypair()
	privKey2, pubKey2 := s.second.NewKeypair()
	return &privateKey{
			scheme: s,
			first:  privKey1,
			second: privKey2,
		}, &publicKey{
			scheme: s,
			first:  pubKey1,
			second: pubKey2,
		}
}

// DeriveSecret derives a shared secret given a private key
// from one party and a public key from another.
func (s *scheme) DeriveSecret(privKey nike.PrivateKey, pubKey nike.PublicKey) []byte {
	return append(privKey.(*privateKey).scheme.first.DeriveSecret(privKey.(*privateKey).first, pubKey.(*publicKey).first),
		privKey.(*privateKey).scheme.second.DeriveSecret(privKey.(*privateKey).second, pubKey.(*publicKey).second)...)
}

// DerivePublicKey derives a public key given a private key.
func (s *scheme) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	return &publicKey{
		scheme: s,
		first:  privKey.(*privateKey).scheme.first.DerivePublicKey(privKey.(*privateKey).first),
		second: privKey.(*privateKey).scheme.second.DerivePublicKey(privKey.(*privateKey).second),
	}
}

// Blind performs the blinding operation against the
// two byte slices and returns the blinded value.
//
// Note that the two arguments must be the correct lengths:
//
// * groupMember must be the size of a public key.
//
// * blindingFactor must be the size of a private key.
//
// See also PublicKey's Blind method.
func (s *scheme) Blind(groupMember []byte, blindingFactor []byte) (blindedGroupMember []byte) {
	if len(groupMember) != s.PublicKeySize() {
		panic("invalid group member size")
	}
	if len(blindingFactor) != s.PrivateKeySize() {
		panic("invalid blinding factor size")
	}
	return append(s.first.Blind(groupMember[:s.first.PublicKeySize()], blindingFactor[:s.first.PrivateKeySize()]),
		s.second.Blind(groupMember[s.first.PublicKeySize():], blindingFactor[s.first.PrivateKeySize():])...)
}

func (s *scheme) NewEmptyPublicKey() nike.PublicKey {
	return &publicKey{
		scheme: s,
		first:  s.first.NewEmptyPublicKey(),
		second: s.second.NewEmptyPublicKey(),
	}
}

// UnmarshalBinaryPublicKey loads a public key from byte slice.
func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (nike.PublicKey, error) {
	pubkey := s.NewEmptyPublicKey()
	err := pubkey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubkey, nil
}

func (p *privateKey) Reset() {
	p.first.Reset()
	p.second.Reset()
}

func (p *privateKey) Bytes() []byte {
	return append(p.first.Bytes(), p.second.Bytes()...)
}

func (p *privateKey) FromBytes(b []byte) error {
	err := p.first.FromBytes(b[:p.scheme.first.PrivateKeySize()])
	if err != nil {
		return err
	}
	return p.second.FromBytes(b[p.scheme.first.PrivateKeySize():])
}

// Blind performs a blinding operation and mutates the public
// key with the blinded value.
func (p *publicKey) Blind(blindingFactor []byte) error {
	err := p.first.Blind(blindingFactor[:p.scheme.first.PublicKeySize()])
	if err != nil {
		return err
	}
	return p.second.Blind(blindingFactor[p.scheme.first.PublicKeySize():])
}

func (p *publicKey) Reset() {
	p.first.Reset()
	p.second.Reset()
}

func (p *publicKey) Bytes() []byte {
	return append(p.first.Bytes(), p.second.Bytes()...)
}

func (p *publicKey) FromBytes(b []byte) error {
	err := p.first.FromBytes(b[:p.scheme.first.PublicKeySize()])
	if err != nil {
		return err
	}
	return p.second.FromBytes(b[p.scheme.first.PublicKeySize():])
}
