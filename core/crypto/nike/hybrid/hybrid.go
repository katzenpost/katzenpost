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
	//privKey.first.
}

// DerivePublicKey derives a public key given a private key.
func (s *scheme) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {

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

}

// UnmarshalBinaryPublicKey loads a public key from byte slice.
func (s *scheme) UnmarshalBinaryPublicKey([]byte) (nike.PublicKey, error) {

}
