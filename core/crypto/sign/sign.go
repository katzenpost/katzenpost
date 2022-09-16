package sign

// Key is an interface for types encapsulating key material.
type Key interface {

	// Reset resets the key material to all zeros.
	Reset()

	// Bytes serializes key material into a byte slice.
	Bytes() []byte

	// FromBytes loads key material from the given byte slice.
	FromBytes(data []byte) error
}

// PrivateKey is an interface for types encapsulating
// private key material.
type PrivateKey interface {
	Key

	Sign(message []byte) (signature []byte)
}

// PublicKey is an interface for types encapsulating
// public key material.
type PublicKey interface {
	Key

	Verify(message []byte) error
}

// Scheme is our signature scheme.
type Scheme interface {

	// SignatureSize returns the size in bytes of the signature.
	SignatureSize() int

	// PublicKeySize returns the size in bytes of the public key.
	PublicKeySize() int

	// PrivateKeySize returns the size in bytes of the private key.
	PrivateKeySize() int

	// NewKeypair returns a newly generated key pair.
	NewKeypair() (PrivateKey, PublicKey)

	// UnmarshalBinaryPublicKey loads a public key from byte slice.
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)

	// UnmarshalBinaryPrivateKey loads a private key from byte slice.
	UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)
}
