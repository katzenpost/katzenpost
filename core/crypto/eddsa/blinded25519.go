// blinded25519.go - blinded EdDSA signatures
// License: AGPL version 3
// Copyright: 2021 - Anonymous contributor

// This module implements the blinded signature scheme as used in
// Tor for OnionV3, see A.2. Tor's key derivation scheme:
// https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt#L2268-L2326
// Note that this implementation of the scheme uses different constants
// for hashing the (factor)s and as thus is not wire format compatible.

// Note that the reason that Tor doesn't need a separate Sign() function
// for blinded private keys is that they use a different in-memory
// representation of secret keys where the nonce seed is stored in expanded
// form (instead of deriving it with sha512 for each signature)

// Note that use of Scalar.SetUniformBytes() is a bit unorthodox:
// The API was designed to take 64 uniformly random bytes,
// which are then reduced mod L. We "abuse" it by providing
// our 32byte scalars as the 32 lower bytes and the upper 32 bytes all-zero
// --- This way we get to initialize Scalar objects without the usual clamping.
// There doesn't seem to be another API that lets us initialize 32-byte scalars
// directly.

// And lastly, note that it would be interesting to come up with a
// blinding scheme that preserves the "validity" of the derived secret key
// for use with x25519, perhaps a way to modify `factor` such that
//            clamp(a)*clamp(factor)
// ===  clamp(clamp(a)*clamp(factor))

package eddsa

import (
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/subtle"
	"encoding"
	"errors"
	"filippo.io/edwards25519"
)

const (
	// BlindFactorSize is the size in bytes of the blinding factors.
	BlindFactorSize = ed25519.PublicKeySize
)

// Sanity checking of public keys.
// We do NOT do check for small-order points here or otherwise validate the point.
// This function is just here to catch accidentally-bad keys, basically.
// Checks that p != G
// Checks that p != 1
// Checks that p != 0
// Checks that L*p = 1
func CheckPublicKey(pk *PublicKey) bool {
	// order is the "L" / order of Curve25519 in little-endian form:
	order_64 := [64]byte{
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c,
		0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x10}
	order_sc, _ := new(edwards25519.Scalar).SetUniformBytes(order_64[:])
	pkA_n , err := new(edwards25519.Point).SetBytes(pk.Bytes())
	if nil != err {
		panic("failed to set edwards25519.Point.SetBytes(), incorrect size?")
	}
	pkA_n.ScalarMult(order_sc, pkA_n)
	identity_element := edwards25519.NewIdentityPoint().Bytes()
	pk_is_1 := subtle.ConstantTimeCompare(identity_element, pk.Bytes())
	pk_mult_L_is_1 := subtle.ConstantTimeCompare(identity_element, pkA_n.Bytes())
	pk_is_G := subtle.ConstantTimeCompare(edwards25519.NewGeneratorPoint().Bytes(),pk.Bytes())

	nulls := [32]byte{}
	pk_is_0 := subtle.ConstantTimeCompare(nulls[:], pk.Bytes())
	if (pk_is_0 << 3) | (pk_is_G << 2) | (pk_is_1 << 1) | pk_mult_L_is_1 == 1 {
		return true
	}
	return false
}

// BlindedPrivateKey encapsulates a blinded PrivateKey.
type BlindedPrivateKey struct {
	blinded ed25519.PrivateKey
}

// Marshal a secret key to 32 bytes.
func (k BlindedPrivateKey) MarshalBinary() (data []byte, err error) {
	if k.blinded == nil || len(k.blinded) == 0 {
		err = errors.New("BlindedPrivateKey.MarshalBinary() empty key")
		return nil, err
	}
	ret := make([]byte, 32)
	copy(ret, k.blinded[:32])
	return ret, err
}

// Unmarshal 32 bytes to a private key. Rederives the public key.
func (k *BlindedPrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		e := errors.New("BlindedPrivatekey.UnmarshalBinary: len(data) != 32")
		return e
	}
	// we could reuse the old k.blinded, but it's easier to throw it away:
	k.blinded = make([]byte, 64)
	copy(k.blinded[:32], data)
	// ns = k.blinded (mod L)
	newsec_scalar, err := new(edwards25519.Scalar).SetUniformBytes(k.blinded)
	if err != nil {
		return err
	}
	// ns * G (mod L)
	pkxA_n := new(edwards25519.Point).ScalarBaseMult(newsec_scalar)
	copy(k.blinded[32:], pkxA_n.Bytes())
	if false == CheckPublicKey(k.PublicKey()) {
		k.blinded = nil
		return errors.New("Invalid marshalled data")
	}
	return nil
}

// static type check ensuring we implement the
// encoding.BinaryMarshaler interface::
var (
	_ encoding.BinaryMarshaler = &BlindedPrivateKey{}
	_ encoding.BinaryUnmarshaler = &BlindedPrivateKey{}
)

// PublicKey returns a PublicKey.
func (b *BlindedPrivateKey) PublicKey() *PublicKey {
	pub := new(PublicKey)
	err := pub.FromBytes(b.blinded[32:])
	if err != nil {
		// This should not be possible:
		panic(err)
	}
	return pub
}

// Sign signs the message msg with the BlindedPrivateKey and returns the signature.
func (b *BlindedPrivateKey) Sign(message []byte) []byte {
	signature := make([]byte, ed25519.SignatureSize)
	// vendored version of ed25519.sign() except it uses the
	// secret/private scalar directly as expandedSecretKey
	// instead of deriving from hash each time.
	// It is a bit unfortunate that this needs to be here...
	blindedSecretKey := [ed25519.PrivateKeySize]byte{}
	copy(blindedSecretKey[:], b.blinded[:32])
	expandedSecretKey := new(edwards25519.Scalar)
	_, err := expandedSecretKey.SetUniformBytes(blindedSecretKey[:])
	if err != nil {
		panic(err)
	}

	// secret_salt <- sha512(private)
	digest1 := sha512.Sum512(b.blinded[:32])

	// very important that nonce is never repeated for different messages;
	// ensured here by deriving nonce from a hash of the message.
	// the second appendix of secret_salt below is not part of the spec:
	// nonce := sha512(secret_salt[32:64] || message || secret_salt[33:64])
	h := sha512.New()
	h.Write(digest1[32:])
	h.Write(message)
	h.Write(digest1[33:])
	messageDigest := h.Sum(nil)

	// messageDigestReduced <- (nonce mod L)
	mdReduced, _ := new(edwards25519.Scalar).SetUniformBytes(messageDigest[:64])

	// R <- messageDigestReduced * B
	encodedR := new(edwards25519.Point).ScalarBaseMult(mdReduced).Bytes()

	// hramDigestReduced := sha512(R || public || message) mod L
	h.Reset()
	h.Write(encodedR)
	h.Write(b.blinded[32:])
	h.Write(message)
	hramDigest := h.Sum(nil)
	hramDigestReduced, _ := new(edwards25519.Scalar).SetUniformBytes(hramDigest[:])
	//     s := (hRamDigestReduced*secret + messageDigestReduced) mod L
	// <-> s := (   (sha512(R || public || message) mod L)*secret
	//            + (nonce mod L)
	//          ) mod L
	s_new := new(edwards25519.Scalar).MultiplyAdd(hramDigestReduced,
		expandedSecretKey,
		mdReduced)

	copy(signature, encodedR)
	copy(signature[32:], s_new.Bytes())
	return signature
}

// Blind performs the blinding operation on the private key
// and returns the BlindedPrivateKey. This function does not
// mutate the PrivateKey.
func (k *PrivateKey) Blind(factor []byte) *BlindedPrivateKey {
	// Here digest is the actual secret key derived from the seed:
	digest := sha512.Sum512(k.Bytes()[:32])
	clamped, err := new(edwards25519.Scalar).SetBytesWithClamping(digest[:32])
	if err != nil {
		panic(err)
	}
	bpk := new(BlindedPrivateKey)
	bpk.blinded = make([]byte, ed25519.PrivateKeySize)
	copy(bpk.blinded[:32], clamped.Bytes())
	return bpk.Blind(factor)
}

// changes the *value* of the slice factor, which points at new bytes
// and does not modify the caller's copy of factor.
func (k *BlindedPrivateKey) Blind(factor []byte) *BlindedPrivateKey {
	if 0 == len(factor) {
		panic("Blind with empty factor")
	}

	sum := sha512.Sum512_256(factor)
	factor = sum[:]
	factor_sc, err := new(edwards25519.Scalar).SetBytesWithClamping(factor)
	if err != nil {
		// This only happens if factor is not 32 bytes.
		panic(err)
	}

	oldsec := make([]byte, ed25519.PrivateKeySize)
	copy(oldsec[:32], k.blinded[:32])
	bb_sc, err := new(edwards25519.Scalar).SetUniformBytes(oldsec)
	if err != nil {
		// This only happens if oldsec is not 32 bytes.
		panic(err)
	}

	// (ab + c) mod l = ScMulAdd(out, a, b, c)
	// a := factor
	// b := k
	// c := 0
	// the (c*B) multiplication here is unfortunate but that was the easiest API
	// to use in edwards25519, so...
	// oo <- factor * bb + 0*B
	oo_sc := new(edwards25519.Scalar).Multiply(factor_sc, bb_sc)

	newsec := make([]byte, ed25519.PrivateKeySize)
	copy(newsec[:32], oo_sc.Bytes())

	// calculates and sets the public key corresponding to the
	// private scalar (used when we have derived a new private scalar)
	newsec_scalar, _ := new(edwards25519.Scalar).SetUniformBytes(newsec)
	pkxA_n := new(edwards25519.Point).ScalarBaseMult(newsec_scalar)
	copy(newsec[32:], pkxA_n.Bytes())

	bpk := new(BlindedPrivateKey)
	bpk.blinded = newsec
	return bpk
}

// Identity returns the key's identity, in this case it's our
// public key in bytes.
func (b *BlindedPrivateKey) Identity() []byte {
	return b.PublicKey().Bytes()
}

// KeyType returns the key type string,
// in this case the constant variable
// whose value is "ed25519".
func (b *BlindedPrivateKey) KeyType() string {
	return keyType
}

// Blind performs the blinding operations on the public key
// and returns the blinded public key. This function does not
// mutate the PublicKey.
func (k *PublicKey) Blind(factor []byte) *PublicKey {
	if 0 == len(factor) {
		panic("Blind with empty factor")
	}

	sum := sha512.Sum512_256(factor)
	factor = sum[:]
	factor_sc, err := new(edwards25519.Scalar).SetBytesWithClamping(factor)
	if err != nil {
		panic("sha512/256 did not return 32 bytes, impossible")
	}
	// out <- factor*pkA + zero*Basepoint
	out, err := new(edwards25519.Point).SetBytes(k.Bytes())
	if err != nil {
		panic("k.Bytes() was not a valid [32]byte slice public key. Was *PublicKey initialized?")
	}
	newkey := new(PublicKey)
	err = newkey.FromBytes(out.ScalarMult(factor_sc, out).Bytes())
	if err != nil {
		// Again this should not happen; but in case it does:
		panic(err)
	}
	return newkey
}
