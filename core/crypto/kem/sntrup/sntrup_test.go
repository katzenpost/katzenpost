// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package sntrup

import (
	"testing"

	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/stretchr/testify/require"
)

func TestSNTRUPKEM(t *testing.T) {
	s := Scheme()

	t.Logf("ciphertext size %d", s.CiphertextSize())
	t.Logf("shared key size %d", s.SharedKeySize())
	t.Logf("private key size %d", s.PrivateKeySize())
	t.Logf("public key size %d", s.PublicKeySize())
	t.Logf("seed size %d", s.SeedSize())
	t.Logf("encapsulation seed size %d", s.EncapsulationSeedSize())

	pubkey1, privkey1, err := s.GenerateKeyPair()
	require.NoError(t, err)
	pubkey2, privkey2, err := s.GenerateKeyPair()
	require.NoError(t, err)

	require.False(t, pubkey1.Equal(pubkey2))
	require.False(t, privkey1.Equal(privkey2))

	pubKey1Blob, err := pubkey1.MarshalBinary()
	require.NoError(t, err)

	pubkey3, err := s.UnmarshalBinaryPublicKey(pubKey1Blob)
	require.NoError(t, err)
	require.True(t, pubkey3.Equal(pubkey1))

	privKey1Blob, err := privkey1.MarshalBinary()
	require.NoError(t, err)
	privkey3, err := s.UnmarshalBinaryPrivateKey(privKey1Blob)
	require.NoError(t, err)
	require.True(t, privkey3.Equal(privkey1))

	ct1, ss1, err := s.Encapsulate(pubkey1)
	require.NoError(t, err)
	require.False(t, utils.CtIsZero(ss1))
	require.False(t, utils.CtIsZero(ct1))

	ss1b, err := s.Decapsulate(privkey1, ct1)
	require.NoError(t, err)
	require.Equal(t, ss1, ss1b)
	t.Logf("our shared key is %x", ss1)

	ct2, ss2, err := s.Encapsulate(pubkey1)
	require.NoError(t, err)
	require.NotEqual(t, ct1, ct2)
	require.NotEqual(t, ss1, ss2)

	seed := make([]byte, s.SeedSize())
	pubkey4, privkey4 := s.DeriveKeyPair(seed)
	encapseed := make([]byte, s.EncapsulationSeedSize())
	ct3, ss3, err := s.EncapsulateDeterministically(pubkey4, encapseed)
	require.NoError(t, err)
	ss3b, err := s.Decapsulate(privkey4, ct3)
	require.NoError(t, err)
	require.Equal(t, ss3, ss3b)
}
