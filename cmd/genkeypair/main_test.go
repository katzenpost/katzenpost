// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/quic/common"
)

func runGenkeypairArgs(args ...string) error {
	cmd := newRootCommand()
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd.Execute()
}

func TestGenkeypairWritesAQUICKeyAndItsPin(t *testing.T) {
	out := filepath.Join(t.TempDir(), "gateway1")
	require.NoError(t, runGenkeypairArgs("--type", "quic", "--out", out), "genkeypair refused --type quic")
	pin, err := os.ReadFile(out + ".quic-tls.hash")
	require.NoError(t, err)
	key, err := common.ReadStaticKey(out + ".quic-tls.key")
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(key.Hash())+"\n", string(pin))

	_, identityPrivateKey, err := signschemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	l, err := common.ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, key, nil)
	require.NoError(t, err)
	defer l.Close()
	u, err := url.Parse("quic://" + l.Addr().String())
	require.NoError(t, err)
	hash, err := hex.DecodeString(string(pin[:len(pin)-1]))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := common.DialURL(u, ctx, nil, hash, nil)
	require.NoError(t, err, "a listener on the generated key did not match its pin")
	conn.Close()
}

func TestGenkeypairRefusesToOverwriteAQUICKey(t *testing.T) {
	for _, existing := range []string{".quic-tls.key", ".quic-tls.hash"} {
		out := filepath.Join(t.TempDir(), "gateway1")
		require.NoError(t, os.WriteFile(out+existing, []byte("keep"), 0o600))
		require.Panics(t, func() { _ = runGenkeypairArgs("--type", "quic", "--out", out) }, existing)
		kept, err := os.ReadFile(out + existing)
		require.NoError(t, err)
		require.Equal(t, "keep", string(kept))
	}
}

func TestGenkeypairRejectsASchemeForQUIC(t *testing.T) {
	out := filepath.Join(t.TempDir(), "gateway1")
	require.Error(t, runGenkeypairArgs("--type", "quic", "--scheme", "ed25519", "--out", out))
	require.NoFileExists(t, out+".quic-tls.key")
}
