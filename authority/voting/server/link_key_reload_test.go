// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
)

func TestNewReloadsTheLinkKeyItGenerated(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	zero := 0
	cfg := &config.Config{
		Server: &config.Server{
			Identifier:         "auth1",
			WireKEMScheme:      "x25519",
			PKISignatureScheme: "Ed25519 Sphincs+",
			DataDir:            dir,
		},
		Logging: &config.Logging{File: filepath.Join(dir, "authority.log"), Level: "ERROR"},
		Debug:   &config.Debug{GenerateOnly: true, MaxPeerConns: &zero, MaxLoopbackConns: &zero},
	}
	_, err := New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
	pubFile := filepath.Join(dir, "link.public.pem")
	first, err := os.ReadFile(pubFile)
	require.NoError(t, err)
	pub, err := kempem.FromPublicPEMFile(pubFile, kemschemes.ByName("x25519"))
	require.NoError(t, err)

	cfg.Authorities = []*config.Authority{{Identifier: "auth1", LinkPublicKey: config.LinkPublicKey{PublicKey: pub}}}
	_, err = New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
	second, err := os.ReadFile(pubFile)
	require.NoError(t, err)
	require.Equal(t, first, second)

	other, _, err := kemschemes.ByName("x25519").GenerateKeyPair()
	require.NoError(t, err)
	cfg.Authorities[0].LinkPublicKey = config.LinkPublicKey{PublicKey: other}
	_, err = New(cfg)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrGenerateOnly)
}
