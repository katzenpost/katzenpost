package eddsa

import (
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"math/rand"
	"time"
	"testing"
	"testing/quick"
)

func bothWork(assertx *assert.Assertions, t require.TestingT, rng io.Reader) bool {
	assert := assertx
	unblinded, err := NewKeypair(rng)
	require.NoError(t, err, "NewKeypair(1)")
	assert.Equal(true, CheckPublicKey(unblinded.PublicKey()))


	factor := make([]byte, BlindFactorSize)
	_, err = rng.Read(factor[:])
	require.NoError(t, err)

	// Blind on uninitialized key should panic:
	bad_public := new(PublicKey)
	assert.Panics(func() { bad_public.Blind(factor) })

	// Test that blinded public+private keys match:
	f1_blind_secret := unblinded.Blind(factor)
	f1_blind_public := unblinded.PublicKey().Blind(factor)
	assert.Equal(f1_blind_secret.Identity(), f1_blind_public.Bytes())
	f1_derived_public := f1_blind_secret.PublicKey()
	assert.Equal(f1_blind_public, f1_derived_public)
	assert.Equal(f1_blind_secret.KeyType(), "ed25519")

	// check public keys: multiply by L and verify we get identity element
	assert.Equal(true, CheckPublicKey(f1_derived_public))

	identity_element := edwards25519.NewIdentityPoint().Bytes()
	assert.NotEqual(identity_element, unblinded.PublicKey())
	assert.NotEqual(identity_element, f1_blind_public)

	f1_blind_secret_ser, err := f1_blind_secret.MarshalBinary()
	assert.Equal(nil, err)
	assert.NotEqual([]byte{}, f1_blind_secret_ser)
	f1_blind_secret_deser := new(BlindedPrivateKey)
	err = f1_blind_secret_deser.UnmarshalBinary(f1_blind_secret_ser)
	assert.Equal(nil, err)
	assert.Equal(f1_blind_secret, f1_blind_secret_deser)
	f1_remarshalled, err := f1_blind_secret_deser.MarshalBinary()
	assert.Equal(nil, err)
	assert.Equal(f1_blind_secret_ser, f1_remarshalled)

	// Check that using the same factor to blind two different keys
	// results in distinct secret + public keys (ie we don't always just return
	// the same secret/public pair)
	unblinded_x, err := NewKeypair(rng)
	require.NoError(t, err, "NewKeypair(2)")
	assert.NotEqual(unblinded_x.Bytes(), unblinded.Bytes())
	f1_blind_public_x := unblinded_x.PublicKey().Blind(factor)
	f1_blind_secret_x := unblinded_x.Blind(factor)
	assert.NotEqual(f1_blind_public, f1_blind_public_x)
	f1_derived_public_x := f1_blind_secret_x.PublicKey()
	assert.Equal(f1_blind_public_x, f1_derived_public_x)
	assert.Equal(true, CheckPublicKey(f1_derived_public_x))

	factor2 := make([]byte, BlindFactorSize)
	_, err = rng.Read(factor2)
	require.NoError(t, err)
	// we just need to ensure that the factors are different,
	// since we hash factor, any bit flip should work.
	assert.NotEqual(factor, factor2)
	f2_blind_secret := unblinded.Blind(factor2)
	f2_blind_public := unblinded.PublicKey().Blind(factor2)
	f2_derived_public := f2_blind_secret.PublicKey()
	assert.Equal(f2_blind_public, f2_derived_public)
	assert.NotEqual(f2_blind_public, f1_blind_public)

	// Ensure that reusing an object for UnmarshalBinary
	// doesn't yield old PublicKey
	f2_blind_secret_ser, err := f2_blind_secret.MarshalBinary()
	assert.Equal(nil, err)
	err = f1_blind_secret_deser.UnmarshalBinary(f2_blind_secret_ser)
	assert.Equal(nil, err)
	assert.Equal(f2_blind_secret, f1_blind_secret_deser)
	nulls := [32]byte{}
	err = f1_blind_secret_deser.UnmarshalBinary(nulls[:])
	assert.NotEqual(nil, err)
	nulls[0] = 1
	err = f1_blind_secret_deser.UnmarshalBinary(nulls[:])
	assert.NotEqual(nil, err)

	// Accidentally blinding with an empty slice should panic:
	assert.Panics(func() { f2_blind_secret.Blind(factor[:0]) })
	assert.Panics(func() { f2_blind_public.Blind(factor[:0]) })

	// exercise some error paths:
	uninit_blind := new(BlindedPrivateKey)
	should_be_empty, err := uninit_blind.MarshalBinary()
	assert.Equal(0, len(should_be_empty))
	assert.NotEqual(nil, err)
	err = uninit_blind.UnmarshalBinary([]byte{})
	assert.NotEqual(nil, err)
	err = uninit_blind.UnmarshalBinary([]byte{2})
	assert.NotEqual(nil, err)

	assert.Equal(true, CheckPublicKey(f1_blind_public))
	assert.Equal(true, CheckPublicKey(f1_blind_public_x))
	assert.Equal(true, CheckPublicKey(f2_blind_public))

	f12_blind_secret := f1_blind_secret.Blind(factor2)
	f21_blind_secret := f2_blind_secret.Blind(factor)
	assert.Equal(f12_blind_secret, f21_blind_secret)
	assert.Equal(f12_blind_secret.PublicKey(), unblinded.Blind(factor).PublicKey().Blind(factor2))
	factor3 := make([]byte, BlindFactorSize)
	_, err = rng.Read(factor3)
	require.NoError(t, err)
	f123_blind_secret := f12_blind_secret.Blind(factor3)
	f213_blind_secret := f21_blind_secret.Blind(factor3)
	f321_blind_secret := unblinded.Blind(factor3).Blind(factor2).Blind(factor)
	assert.Equal(f123_blind_secret, f213_blind_secret)
	assert.Equal(f321_blind_secret, f123_blind_secret)
	assert.NotEqual(f123_blind_secret, f12_blind_secret)
	f123_blind_public := unblinded.PublicKey().Blind(factor).Blind(factor2).Blind(factor3)
	assert.Equal(f123_blind_secret.PublicKey(), f123_blind_public)
	assert.Equal(true, CheckPublicKey(f123_blind_public))
	assert.NotEqual(identity_element, f123_blind_public)

	// Check signature creation and validation:
	msg := [5]byte{'a', 'b', 'c', 'd', 'e'}
	msg_x := [5]byte{'a', 'b', 'c', 'd', 'x'}
	f1_sig := f1_blind_secret.Sign(msg[:])
	f2_sig := f2_blind_secret.Sign(msg[:])
	f1_res1 := f1_blind_public.Verify(f1_sig[:], msg[:])
	f2_res1 := f2_blind_public.Verify(f2_sig[:], msg[:])
	assert.Equal(true, f1_res1)
	assert.Equal(true, f2_res1)
	sig123 := f123_blind_secret.Sign(msg[:])
	assert.Equal(true, f123_blind_public.Verify(sig123, msg[:]))

	// signature: (R,s)  ;  check that s < L:
	// the new edwards25519 library doesn't export ScMinimal (scMinimal),
	// but it carries the function under the name "isReduced" which is
	// called from Scalar.SetCanonicalBytes(), so by looking at the (err)
	// from that we can determine the outcome:
	// nil | ScMinimal(s) === true
	// err | ScMinimal(s) === false
	f1_sig_s := [32]byte{}
	copy(f1_sig_s[:], f1_sig[32:])
	// old: assert.Equal(true, edwards25519.ScMinimal(&f1_sig_s))
	_, scMinimal := new(edwards25519.Scalar).SetCanonicalBytes(f1_sig_s[:])
	assert.Equal(nil, scMinimal)
	f2_sig_s := [32]byte{}
	copy(f2_sig_s[:], f2_sig[32:])
	_, scMinimal = new(edwards25519.Scalar).SetCanonicalBytes(f2_sig_s[:])
	//assert.Equal(true, edwards25519.ScMinimal(&f2_sig_s))
	assert.Equal(nil, scMinimal)

	// Check that giving arguments in wrong order doesn't work:
	f2_res2_wrong_arg_order := f2_blind_public.Verify(msg[:], f2_sig[:])
	assert.Equal(false, f2_res2_wrong_arg_order)

	// Check that we can't verify messages with the other's PK:
	f1_res3 := f1_blind_public.Verify(f2_sig[:], msg[:])
	f2_res3 := f2_blind_public.Verify(f1_sig[:], msg[:])
	assert.Equal(false, f1_res3)
	assert.Equal(false, f2_res3)

	// Check that the signature contains the message:
	f1_res4 := f1_blind_public.Verify(f1_sig[:], msg_x[:])
	assert.Equal(false, f1_res4)

	// Checking a random "signature" should obviously fail:
	random_sig := [64]byte{}
	f1_res5 := f1_blind_public.Verify(random_sig[:], msg[:])
	assert.Equal(false, f1_res5)

	return true
}

func TestBlinding(t *testing.T) {
	t.Parallel()
	assertx := assert.New(t)
	test_seed := time.Now().UnixNano()
	rng := rand.New(rand.NewSource(test_seed))
	t.Log("TestBlinding test_seed", test_seed)
	config := &quick.Config{Rand: rng}
	assert_bothwork := func() bool { return bothWork(assertx, t, rng) }
	if err := quick.Check(assert_bothwork, config); err != nil {
		t.Error("failed bothwork", err)
	}
}
