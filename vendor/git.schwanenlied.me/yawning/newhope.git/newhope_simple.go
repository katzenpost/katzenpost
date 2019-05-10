// newhope_simple.go - NewHope-Simple interface.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to newhope, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package newhope

import (
	"io"

	"golang.org/x/crypto/sha3"
)

const (
	// HighBytes is the length of the encoded secret in bytes.
	HighBytes = 384

	// SendASimpleSize is the length of Alice's NewHope-Simple public key in
	// bytes.
	SendASimpleSize = PolyBytes + SeedBytes

	// SendBSimpleSize is the length of Bob's NewHope-Simple public key in
	// bytes.
	SendBSimpleSize = PolyBytes + HighBytes
)

func encodeBSimple(r []byte, b *poly, v *poly) {
	b.toBytes(r)
	v.compress(r[PolyBytes:])
}

func decodeBSimple(b *poly, v *poly, r []byte) {
	b.fromBytes(r)
	v.decompress(r[PolyBytes:])
}

// PublicKeySimpleAlice is Alice's NewHope-Simple public key.
type PublicKeySimpleAlice struct {
	Send [SendASimpleSize]byte
}

// PrivateKeySimpleAlice is Alice's NewHope-Simple private key.
type PrivateKeySimpleAlice struct {
	sk poly
}

// Reset clears all sensitive information such that it no longer appears in
// memory.
func (k *PrivateKeySimpleAlice) Reset() {
	k.sk.reset()
}

// GenerateKeyPairSimpleAlice returns a NewHope-Simple private/public key pair.
// The private key is generated using the given reader, which must return
// random data.  The receiver side of the key exchange (aka "Bob") MUST use
// KeyExchangeSimpleBob() instead of this routine.
func GenerateKeyPairSimpleAlice(rand io.Reader) (*PrivateKeySimpleAlice, *PublicKeySimpleAlice, error) {
	var a, e, pk, r poly
	var seed, noiseSeed [SeedBytes]byte

	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, nil, err
	}
	seed = sha3.Sum256(seed[:]) // Don't send output of system RNG.
	a.uniform(&seed, TorSampling)

	if _, err := io.ReadFull(rand, noiseSeed[:]); err != nil {
		return nil, nil, err
	}
	defer memwipe(noiseSeed[:])

	privKey := new(PrivateKeySimpleAlice)
	privKey.sk.getNoise(&noiseSeed, 0)
	privKey.sk.ntt()
	e.getNoise(&noiseSeed, 1)
	e.ntt()

	pubKey := new(PublicKeySimpleAlice)
	r.pointwise(&privKey.sk, &a)
	pk.add(&e, &r)
	encodeA(pubKey.Send[:], &pk, &seed)

	return privKey, pubKey, nil
}

// PublicKeySimpleBob is Bob's NewHope-Simple public key.
type PublicKeySimpleBob struct {
	Send [SendBSimpleSize]byte
}

// KeyExchangeSimpleBob is the Responder side of the NewHope-Simple key
// exchange.  The shared secret and "public key" are generated using the
// given reader, which must return random data.
func KeyExchangeSimpleBob(rand io.Reader, alicePk *PublicKeySimpleAlice) (*PublicKeySimpleBob, []byte, error) {
	var pka, a, sp, ep, bp, v, epp, m poly
	var seed, noiseSeed [SeedBytes]byte

	if _, err := io.ReadFull(rand, noiseSeed[:]); err != nil {
		return nil, nil, err
	}
	defer memwipe(noiseSeed[:])

	var sharedKey [SharedSecretSize]byte
	if _, err := io.ReadFull(rand, sharedKey[:]); err != nil {
		return nil, nil, err
	}
	defer memwipe(sharedKey[:])
	sharedKey = sha3.Sum256(sharedKey[:])
	m.fromMsg(sharedKey[:])

	decodeA(&pka, &seed, alicePk.Send[:])
	a.uniform(&seed, TorSampling)

	sp.getNoise(&noiseSeed, 0)
	sp.ntt()
	ep.getNoise(&noiseSeed, 1)
	ep.ntt()

	bp.pointwise(&a, &sp)
	bp.add(&bp, &ep)

	v.pointwise(&pka, &sp)
	v.invNtt()

	epp.getNoise(&noiseSeed, 2)
	v.add(&v, &epp)
	v.add(&v, &m) // add key

	pubKey := new(PublicKeySimpleBob)
	encodeBSimple(pubKey.Send[:], &bp, &v)
	mu := sha3.Sum256(sharedKey[:])

	// Scrub the sensitive stuff...
	sp.reset()
	v.reset()
	m.reset()

	return pubKey, mu[:], nil
}

// KeyExchangeSimpleAlice is the Initiaitor side of the NewHope-Simple key
// exchange.  The provided private key is obliterated prior to returning.
func KeyExchangeSimpleAlice(bobPk *PublicKeySimpleBob, aliceSk *PrivateKeySimpleAlice) ([]byte, error) {
	var v, bp, k poly

	decodeBSimple(&bp, &v, bobPk.Send[:])
	k.pointwise(&aliceSk.sk, &bp)
	k.invNtt()

	k.sub(&k, &v)

	var sharedKey [SharedSecretSize]byte
	k.toMsg(sharedKey[:])

	// mu <- Sha3-256(v')
	mu := sha3.Sum256(sharedKey[:])

	// Scrub the sensitive stuff...
	memwipe(sharedKey[:])
	k.reset()
	aliceSk.Reset()

	return mu[:], nil
}
