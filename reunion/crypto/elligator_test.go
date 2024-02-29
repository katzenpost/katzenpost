/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package crypto

import (
	"testing"

	"github.com/katzenpost/hpqc/rand"
	"github.com/stretchr/testify/require"
)

func TestPrivateKey(t *testing.T) {
	require := require.New(t)

	privateKey := NewRandomPrivateKey()
	privateKey2 := NewEmptyPrivateKey()
	err := privateKey2.FromBytes(privateKey.Bytes())
	require.NoError(err)
	require.Equal(privateKey.Bytes(), privateKey2.Bytes())
}

func TestPublicKey(t *testing.T) {
	require := require.New(t)

	publicKey := new(PublicKey)
	fu := [32]byte{}
	_, err := rand.Reader.Read(fu[:])
	require.NoError(err)

	err = publicKey.FromBytes(fu[:])
	require.NoError(err)
	publicKey2 := new(PublicKey)
	err = publicKey2.FromBytes(publicKey.Bytes()[:])
	require.NoError(err)
	require.Equal(publicKey.Bytes(), publicKey2.Bytes())
}

func TestRepresentativeKey(t *testing.T) {
	require := require.New(t)

	representativeKey := new(Representative)
	fu := [32]byte{}
	_, err := rand.Reader.Read(fu[:])
	require.NoError(err)

	err = representativeKey.FromBytes(fu[:])
	require.NoError(err)
	representativeKey2 := new(Representative)
	err = representativeKey2.FromBytes(representativeKey.Bytes()[:])
	require.NoError(err)
	require.Equal(representativeKey.Bytes(), representativeKey2.Bytes())
}

// TestNewKeypair tests Curve25519/Elligator keypair generation.
func TestNewKeypair(t *testing.T) {
	// Test standard Curve25519 first.
	keypair, err := NewKeypair(false)
	if err != nil {
		t.Fatal("NewKeypair(false) failed:", err)
	}
	if keypair == nil {
		t.Fatal("NewKeypair(false) returned nil")
	}
	if keypair.HasElligator() {
		t.Fatal("NewKeypair(false) has a Elligator representative")
	}

	// Test Elligator generation.
	keypair, err = NewKeypair(true)
	if err != nil {
		t.Fatal("NewKeypair(true) failed:", err)
	}
	if keypair == nil {
		t.Fatal("NewKeypair(true) returned nil")
	}
	if !keypair.HasElligator() {
		t.Fatal("NewKeypair(true) mising an Elligator representative")
	}
}

func TestNewKeypairSerialization(t *testing.T) {
	require := require.New(t)

	keypair, err := NewKeypair(true)
	require.NoError(err)

	fu, err := keypair.MarshalBinary()
	require.NoError(err)

	keypair2, err := NewKeypair(true)
	require.NoError(err)
	err = keypair2.UnmarshalBinary(fu)
	require.NoError(err)

	fu2, err := keypair2.MarshalBinary()
	require.NoError(err)
	require.Equal(fu, fu2)
}
