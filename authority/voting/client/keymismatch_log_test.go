// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
)

func mismatchLog(t *testing.T) (*authorityAuthenticator, func() string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "auth.log")
	lb, err := log.New(p, "WARNING", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = lb.Close() })
	id, _, err := signschemes.ByName("Ed25519 Sphincs+").GenerateKey()
	require.NoError(t, err)
	link, _, err := kemschemes.ByName("x25519").GenerateKeyPair()
	require.NoError(t, err)
	a := &authorityAuthenticator{name: "auth-a", IdentityPublicKey: id, LinkPublicKey: link, log: lb.GetLogger("auth")}
	return a, func() string {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		return string(b)
	}
}

func TestIdentityMismatchLogNamesAuthority(t *testing.T) {
	a, out := mismatchLog(t)
	got := make([]byte, hash.HashSize)
	want := hash.Sum256From(a.IdentityPublicKey)
	require.False(t, a.IsPeerValid(&wire.PeerCredentials{AdditionalData: got}))
	require.Contains(t, out(), fmt.Sprintf("authority %q: identity key hash mismatch (expected=%x, received=%x)", "auth-a", want[:], got))
}

func TestLinkMismatchLogNamesAuthority(t *testing.T) {
	a, out := mismatchLog(t)
	other, _, err := kemschemes.ByName("x25519").GenerateKeyPair()
	require.NoError(t, err)
	want := hash.Sum256From(a.IdentityPublicKey)
	require.False(t, a.IsPeerValid(&wire.PeerCredentials{AdditionalData: want[:], PublicKey: other}))
	require.Contains(t, out(), fmt.Sprintf("authority %q: link key mismatch (expected=%x, received=%x)", "auth-a", hash.Sum256From(a.LinkPublicKey), hash.Sum256From(other)))
}

func TestLinkMismatchWithoutKeyNamesAuthority(t *testing.T) {
	a, out := mismatchLog(t)
	want := hash.Sum256From(a.IdentityPublicKey)
	require.NotPanics(t, func() {
		require.False(t, a.IsPeerValid(&wire.PeerCredentials{AdditionalData: want[:]}))
	})
	require.Contains(t, out(), fmt.Sprintf("authority %q: link key mismatch", "auth-a"))
}
