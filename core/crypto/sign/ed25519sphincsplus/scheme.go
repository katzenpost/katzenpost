package ed25519sphincsplus

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/core/crypto/pem"
	"github.com/katzenpost/katzenpost/core/crypto/sign"

	sphincs "github.com/katzenpost/katzenpost/sphincsplus/ref"
)

var (
	ErrPrivateKeySize = errors.New("byte slice length must match PrivateKeySize")
	ErrPublicKeySize  = errors.New("byte slice length must match PublicKeySize")
	PrivateKeyType = "ED25519 SPHINCS+ PRIVATE KEY"
	PublicKeyType = "ED25519 SPHINCS+ PUBLIC KEY"
	// Scheme implements our sign.Scheme interface using the ed25519 wrapper.
	Scheme = &scheme{}
)

type scheme struct{}

var _ sign.Scheme = (*scheme)(nil)

func (s *scheme) NewKeypair() (sign.PrivateKey, sign.PublicKey) {
	eprivKey, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}
	epubKey := eprivKey.PublicKey()
	sprivKey, spubKey := sphincs.NewKeypair()
	privKey := &privateKey{
		e: eprivKey,
		s: sprivKey,
	}
	pubKey := &publicKey{
		e: epubKey,
		s: spubKey,
	}
	pubKey.hash = blake2b.Sum256(pubKey.Bytes())
	return privKey, pubKey
}

func (s *scheme) NewEmptyPublicKey() sign.PublicKey {
	return NewEmptyPublicKey()
}

func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	pubKey := NewEmptyPublicKey()
	err := pubKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	privKey := NewEmptyPrivateKey()
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func (s *scheme) UnmarshalTextPublicKey(text []byte) (sign.PublicKey, error) {
	pubKey := NewEmptyPublicKey()
	err := pubKey.UnmarshalText(text)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (s *scheme) SignatureSize() int {
	return eddsa.SignatureSize + sphincs.SignatureSize
}

func (s *scheme) PublicKeySize() int {
	return eddsa.PublicKeySize + sphincs.PublicKeySize
}

func (s *scheme) PrivateKeySize() int {
	return eddsa.PrivateKeySize + sphincs.PrivateKeySize
}

func (s *scheme) Name() string {
	return "Ed25519 Sphincs+"
}

func (s *scheme) PrivateKeyType() string {
	return PrivateKeyType
}

func (s *scheme) PublicKeyType() string {
	return PublicKeyType
}

type privateKey struct {
	e *eddsa.PrivateKey
	s *sphincs.PrivateKey
}

func NewEmptyPrivateKey() *privateKey {
	return &privateKey{
		e: new(eddsa.PrivateKey),
		s: new(sphincs.PrivateKey),
	}
}

func (p *privateKey) KeyType() string {
	return PrivateKeyType
}

func (p *privateKey) Sign(message []byte) (signature []byte) {
	return append(p.e.Sign(message),
		p.s.Sign(message)...)
}

func (p *privateKey) Reset() {
	p.e.Reset()
	p.s.Reset()
}

func (p *privateKey) Bytes() []byte {
	return append(p.e.Bytes(),
		p.s.Bytes()...)
}

func (p *privateKey) FromBytes(data []byte) error {
	if len(data) != eddsa.PrivateKeySize+sphincs.PrivateKeySize {
		return ErrPrivateKeySize
	}
	err := p.e.FromBytes(data[:eddsa.PrivateKeySize])
	if err != nil {
		return err
	}
	err = p.s.FromBytes(data[eddsa.PrivateKeySize:])
	if err != nil {
		return err
	}
	return nil
}

type publicKey struct {
	e    *eddsa.PublicKey
	s    *sphincs.PublicKey
	hash [32]byte
}

func NewEmptyPublicKey() *publicKey {
	return &publicKey{
		e: new(eddsa.PublicKey),
		s: new(sphincs.PublicKey),
	}
}

func (p *publicKey) KeyType() string {
	return PublicKeyType
}

func (p *publicKey) Sum256() [32]byte {
	return p.hash
}

func (p *publicKey) Equal(pubKey sign.PublicKey) bool {
	return hmac.Equal(pubKey.Bytes(), p.Bytes())
}

func (p *publicKey) Verify(signature, message []byte) bool {
	if !p.e.Verify(signature[:eddsa.SignatureSize], message) {
		return false
	}
	if !p.s.Verify(signature[eddsa.SignatureSize:], message) {
		return false
	}
	return true
}

func (p *publicKey) Reset() {
	p.e.Reset()
	p.s.Reset()
}

func (p *publicKey) Bytes() []byte {
	return append(p.e.Bytes(),
		p.s.Bytes()...)
}

func (p *publicKey) FromBytes(data []byte) error {
	if len(data) != eddsa.PublicKeySize+sphincs.PublicKeySize {
		return ErrPublicKeySize
	}
	err := p.e.FromBytes(data[:eddsa.PublicKeySize])
	if err != nil {
		return err
	}
	err = p.s.FromBytes(data[eddsa.PublicKeySize:])
	if err != nil {
		return err
	}
	p.hash = blake2b.Sum256(p.Bytes())
	return nil
}

func (p *publicKey) MarshalText() (text []byte, err error) {
	return pem.ToPEMBytes(p), nil
}

func (p *publicKey) UnmarshalText(text []byte) error {
	return pem.FromPEMBytes(text, p)
}

func (p *publicKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *publicKey) UnmarshalBinary(bytes []byte) error {
	return p.FromBytes(bytes)
}
