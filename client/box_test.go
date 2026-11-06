// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/hybrid"
	"github.com/katzenpost/hpqc/protocols/sealedbox"

	"github.com/katzenpost/katzenpost/client/thin"
)

func TestDaemonBoxSeal(t *testing.T) {
	d, appID, responseCh := newVoucherTestDaemon(t)
	nike := hybrid.X25519CTIDH1024
	pub, priv, err := nike.GenerateKeyPair()
	require.NoError(t, err)

	d.boxSeal(&Request{AppID: appID, BoxSeal: &thin.BoxSeal{
		NIKEScheme: nike.Name(), PublicKey: pub.Bytes(), Plaintext: []byte("voucher"),
	}})
	reply := awaitResponse(t, responseCh).BoxSealReply
	require.NotNil(t, reply)
	require.Equal(t, thin.ThinClientSuccess, reply.ErrorCode)

	got, err := sealedbox.NewScheme(nike).Open(priv, pub, reply.Ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("voucher"), got)
}

func TestDaemonBoxSealRejects(t *testing.T) {
	d, appID, responseCh := newVoucherTestDaemon(t)
	pub, _, err := hybrid.X25519CTIDH1024.GenerateKeyPair()
	require.NoError(t, err)

	for _, req := range []*thin.BoxSeal{
		{NIKEScheme: "no-such-nike", PublicKey: pub.Bytes(), Plaintext: []byte("v")},
		{NIKEScheme: "X25519-CTIDH1024", PublicKey: []byte("short"), Plaintext: []byte("v")},
	} {
		d.boxSeal(&Request{AppID: appID, BoxSeal: req})
		reply := awaitResponse(t, responseCh).BoxSealReply
		require.NotNil(t, reply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, reply.ErrorCode)
		require.Empty(t, reply.Ciphertext)
	}
}

func TestDaemonNIKEAndBoxRoundTrip(t *testing.T) {
	d, appID, responseCh := newVoucherTestDaemon(t)
	scheme := "X25519-CTIDH1024"
	keyPair := func() *thin.NIKEGenerateKeyPairReply {
		d.nikeGenerateKeyPair(&Request{AppID: appID, NIKEGenerateKeyPair: &thin.NIKEGenerateKeyPair{NIKEScheme: scheme}})
		reply := awaitResponse(t, responseCh).NIKEGenerateKeyPairReply
		require.Equal(t, thin.ThinClientSuccess, reply.ErrorCode)
		return reply
	}
	alice, bob := keyPair(), keyPair()

	derive := func(priv, pub []byte) []byte {
		d.nikeDeriveSecret(&Request{AppID: appID, NIKEDeriveSecret: &thin.NIKEDeriveSecret{
			NIKEScheme: scheme, PrivateKey: priv, PublicKey: pub,
		}})
		reply := awaitResponse(t, responseCh).NIKEDeriveSecretReply
		require.Equal(t, thin.ThinClientSuccess, reply.ErrorCode)
		return reply.SharedSecret
	}
	ss := derive(alice.PrivateKey, bob.PublicKey)
	require.NotEmpty(t, ss)
	require.Equal(t, ss, derive(bob.PrivateKey, alice.PublicKey))

	d.boxSeal(&Request{AppID: appID, BoxSeal: &thin.BoxSeal{
		NIKEScheme: scheme, PublicKey: bob.PublicKey, Plaintext: []byte("voucher"),
	}})
	ct := awaitResponse(t, responseCh).BoxSealReply.Ciphertext

	open := func(priv []byte) *thin.BoxOpenReply {
		d.boxOpen(&Request{AppID: appID, BoxOpen: &thin.BoxOpen{NIKEScheme: scheme, PrivateKey: priv, Ciphertext: ct}})
		return awaitResponse(t, responseCh).BoxOpenReply
	}
	reply := open(bob.PrivateKey)
	require.Equal(t, thin.ThinClientSuccess, reply.ErrorCode)
	require.Equal(t, []byte("voucher"), reply.Plaintext)
	reply = open(alice.PrivateKey)
	require.Equal(t, thin.ThinClientErrorInvalidRequest, reply.ErrorCode)
	require.Empty(t, reply.Plaintext)
}

func TestDaemonNIKERejects(t *testing.T) {
	d, appID, responseCh := newVoucherTestDaemon(t)
	d.nikeGenerateKeyPair(&Request{AppID: appID, NIKEGenerateKeyPair: &thin.NIKEGenerateKeyPair{NIKEScheme: "no-such-nike"}})
	require.Equal(t, thin.ThinClientErrorInvalidRequest, awaitResponse(t, responseCh).NIKEGenerateKeyPairReply.ErrorCode)

	pub, priv, err := hybrid.X25519CTIDH1024.GenerateKeyPair()
	require.NoError(t, err)
	for _, req := range []*thin.NIKEDeriveSecret{
		{NIKEScheme: "no-such-nike", PrivateKey: priv.Bytes(), PublicKey: pub.Bytes()},
		{NIKEScheme: "X25519-CTIDH1024", PrivateKey: []byte("short"), PublicKey: pub.Bytes()},
		{NIKEScheme: "X25519-CTIDH1024", PrivateKey: priv.Bytes(), PublicKey: []byte("short")},
	} {
		d.nikeDeriveSecret(&Request{AppID: appID, NIKEDeriveSecret: req})
		reply := awaitResponse(t, responseCh).NIKEDeriveSecretReply
		require.Equal(t, thin.ThinClientErrorInvalidRequest, reply.ErrorCode)
		require.Empty(t, reply.SharedSecret)
	}

	d.boxOpen(&Request{AppID: appID, BoxOpen: &thin.BoxOpen{NIKEScheme: "X25519-CTIDH1024", PrivateKey: priv.Bytes(), Ciphertext: []byte("short")}})
	require.Equal(t, thin.ThinClientErrorInvalidRequest, awaitResponse(t, responseCh).BoxOpenReply.ErrorCode)
}
