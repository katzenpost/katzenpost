// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/hybrid"
	"github.com/katzenpost/hpqc/protocols/box"

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

	got, err := box.NewScheme(nike).Open(priv, pub, reply.Ciphertext)
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
