// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package sntrup

import (
	"testing"

	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/stretchr/testify/require"
)

func TestSNTRUPKEMOnly(t *testing.T) {
	s := Scheme()

	t.Logf("ciphertext size %d", s.CiphertextSize())
	t.Logf("shared key size %d", s.SharedKeySize())
	t.Logf("private key size %d", s.PrivateKeySize())
	t.Logf("public key size %d", s.PublicKeySize())
	t.Logf("seed size %d", s.SeedSize())
	t.Logf("encapsulation seed size %d", s.EncapsulationSeedSize())

	pubkey1, privkey1, err := s.GenerateKeyPair()
	require.NoError(t, err)
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
}
