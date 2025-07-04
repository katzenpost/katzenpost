package x448

import (
	"crypto/subtle"

	fp "github.com/katzenpost/circl/math/fp448"
)

// Size is the length in bytes of a X448 key.
const Size = 56

// Key represents a X448 key.
type Key [Size]byte

func (k *Key) clamp(in *Key) *Key {
	*k = *in
	k[0] &= 252
	k[55] |= 128
	return k
}

// isValidPubKey verifies if the public key is not a low-order point.
func (k *Key) isValidPubKey() bool {
	fp.Modp((*fp.Elt)(k))
	var isLowOrder int
	for _, P := range lowOrderPoints {
		isLowOrder |= subtle.ConstantTimeCompare(P[:], k[:])
	}
	return isLowOrder == 0
}

// KeyGen obtains a public key given a secret key.
func KeyGen(public, secret *Key) {
	ladderJoye(public.clamp(secret))
}

// Shared calculates Alice's shared key from Alice's secret key and Bob's
// public key returning true on success. A failure case happens when the public
// key is a low-order point, thus the shared key is all-zeros and the function
// returns false.
func Shared(shared, secret, public *Key) bool {
	validPk := *public
	ok := validPk.isValidPubKey()
	ladderMontgomery(shared.clamp(secret), &validPk)
	return ok
}
