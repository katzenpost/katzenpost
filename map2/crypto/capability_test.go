// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCapabilties(t *testing.T) {
	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	alice := DuplexFromSeed(true, seed)
	bob := DuplexFromSeed(false, seed)

	aliceMesg1 := []byte("hello bob")
	addr1 := []byte("addr 1")

	aliceWriteCap1 := alice.WriteOnlyCap.WriteCapForAddr(addr1, aliceMesg1)
	require.True(t, aliceWriteCap1.Verify())
	// mutate cap's payload such that the signature verification fails
	aliceWriteCap1.Payload = []byte("blah blah fake payload")
	require.False(t, aliceWriteCap1.Verify())

	bobReadCap1 := bob.ReadOnlyCap.ReadCapForAddr(addr1)
	require.True(t, bobReadCap1.Verify())

	bobMesg1 := []byte("hello alice")
	addr2 := []byte("addr 2")

	bobWriteCap1 := bob.WriteOnlyCap.WriteCapForAddr(addr2, bobMesg1)
	require.True(t, bobWriteCap1.Verify())
	// mutate cap's payload such that the signature verification fails
	bobWriteCap1.Payload = []byte("blah blah fake payload")
	require.False(t, aliceWriteCap1.Verify())

	aliceReadCap1 := alice.ReadOnlyCap.ReadCapForAddr(addr2)
	require.True(t, aliceReadCap1.Verify())
}
