package hybrid

import (
	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ctidh"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var CTIDHX25519 nike.Scheme = &scheme{
	name:   "CTIDH-X25519",
	first:  ctidh.CTIDHScheme,
	second: ecdh.NewEcdhNike(rand.Reader),
}

type publicKey struct {
	scheme *scheme
	first  nike.PublicKey
	second nike.PublicKey
}

type privateKey struct {
	scheme *scheme
	first  nike.PrivateKey
	second nike.PrivateKey
}

type scheme struct {
	name   string
	first  nike.Scheme
	second nike.Scheme
}

func (s *scheme) PublicKeySize() int {
	return s.first.PublicKeySize() + s.second.PublicKeySize()
}

func (s *scheme) PrivateKeySize() int {
	return s.first.PrivateKeySize() + s.second.PrivateKeySize()
}

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

func (s *scheme) DeriveSecret(privKey nike.PrivateKey, pubKey nike.PublicKey) []byte {
	return append(privKey.(*privateKey).scheme.first.DeriveSecret(privKey.(*privateKey).first, pubKey.(*publicKey).first),
		privKey.(*privateKey).scheme.second.DeriveSecret(privKey.(*privateKey).second, pubKey.(*publicKey).second)...)
}

func (s *scheme) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	return &publicKey{
		scheme: s,
		first:  privKey.(*privateKey).scheme.first.DerivePublicKey(privKey.(*privateKey).first),
		second: privKey.(*privateKey).scheme.second.DerivePublicKey(privKey.(*privateKey).second),
	}
}

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
