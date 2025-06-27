package sphincsplus

//#cgo linux LDFLAGS: "-L./ -L/usr/lib/x86_64-linux-gnu/ -lcrypto"
//#include "api.h"
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/katzenpost/hpqc/util"

	"github.com/katzenpost/sphincsplus/ref/params"
)

var (
	_ = params.A

	// PublicKeySize is the size in bytes of the public key.
	PublicKeySize int = C.CRYPTO_PUBLICKEYBYTES

	// PrivateKeySize is the size in bytes of the private key.
	PrivateKeySize int = C.CRYPTO_SECRETKEYBYTES

	// SignatureSize is the size in bytes of the signature.
	SignatureSize int = C.CRYPTO_BYTES

	// ErrPublicKeySize indicates the raw data is not the correct size for a public key.
	ErrPublicKeySize error = fmt.Errorf("%s: raw public key data size is wrong", Name())

	// ErrPrivateKeySize indicates the raw data is not the correct size for a private key.
	ErrPrivateKeySize error = fmt.Errorf("%s: raw private key data size is wrong", Name())
)

// Name returns the string naming of the current
// Sphincs+ that this binding is being used with.
func Name() string {
	return "Sphincs+shake-256f"
}

// NewKeypair generates a new Sphincs+ keypair.
func NewKeypair() (*PrivateKey, *PublicKey) {
	privKey := &PrivateKey{
		privateKey: make([]byte, C.CRYPTO_SECRETKEYBYTES),
	}
	pubKey := &PublicKey{
		publicKey: make([]byte, C.CRYPTO_PUBLICKEYBYTES),
	}
	C.crypto_sign_keypair((*C.uchar)(unsafe.Pointer(&pubKey.publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&privKey.privateKey[0])))
	return privKey, pubKey
}

// PublicKey is a public Sphincs+ key.
type PublicKey struct {
	publicKey []byte
}

// Reset overwrites the key with zeros.
func (p *PublicKey) Reset() {
	util.ExplicitBzero(p.publicKey)
}

// Verify checks whether the given signature is valid.
func (p *PublicKey) Verify(signature, message []byte) bool {
	ret := C.crypto_sign_verify((*C.uchar)(unsafe.Pointer(&signature[0])),
		C.size_t(len(signature)),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
		(*C.uchar)(unsafe.Pointer(&p.publicKey[0])))
	if ret == 0 {
		return true
	}
	return false
}

// Bytes returns the PublicKey as a byte slice.
func (p *PublicKey) Bytes() []byte {
	out := make([]byte, len(p.publicKey))
	copy(out, p.publicKey)
	return out
}

// FromBytes loads a PublicKey from the given byte slice.
func (p *PublicKey) FromBytes(data []byte) error {
	if len(data) != PublicKeySize {
		return ErrPublicKeySize
	}

	p.publicKey = make([]byte, len(data))
	copy(p.publicKey, data)
	return nil
}

// PrivateKey is a private Sphincs+ key.
type PrivateKey struct {
	privateKey []byte
}

// Reset overwrites the key with zeros.
func (p *PrivateKey) Reset() {
	util.ExplicitBzero(p.privateKey)
}

// Sign signs the given message and returns the signature.
func (p *PrivateKey) Sign(message []byte) []byte {
	signature := make([]byte, C.CRYPTO_BYTES)
	sigLen := C.size_t(C.CRYPTO_BYTES)
	C.crypto_sign_signature((*C.uchar)(unsafe.Pointer(&signature[0])),
		&sigLen,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(C.size_t)(len(message)),
		(*C.uchar)(unsafe.Pointer(&p.privateKey[0])))
	return signature
}

// Bytes returns the PrivateKey as a byte slice.
func (p *PrivateKey) Bytes() []byte {
	out := make([]byte, len(p.privateKey))
	copy(out, p.privateKey)
	return out
}

// FromBytes loads a PrivateKey from the given byte slice.
func (p *PrivateKey) FromBytes(data []byte) error {
	if len(data) != PrivateKeySize {
		return ErrPrivateKeySize
	}

	p.privateKey = make([]byte, len(data))
	copy(p.privateKey, data)
	return nil
}
