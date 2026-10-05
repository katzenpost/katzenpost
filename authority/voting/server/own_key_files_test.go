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

func ownKeyConfig(t *testing.T) (*config.Config, string) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	lkPub, lkPriv, err := kemschemes.ByName("x25519").GenerateKeyPair()
	require.NoError(t, err)
	require.NoError(t, kempem.PrivateKeyToFile(filepath.Join(dir, "link.key"), lkPriv))
	require.NoError(t, kempem.PublicKeyToFile(filepath.Join(dir, "link.pub"), lkPub))
	zero := 0
	return &config.Config{
		Server: &config.Server{
			Identifier:             "auth1",
			WireKEMScheme:          "x25519",
			PKISignatureScheme:     "Ed25519 Sphincs+",
			DataDir:                dir,
			IdentityPrivateKeyFile: "id.key",
			IdentityPublicKeyFile:  filepath.Join(dir, "id.pub"),
			LinkPrivateKeyFile:     "link.key",
			LinkPublicKeyFile:      filepath.Join(dir, "link.pub"),
		},
		Authorities: []*config.Authority{{Identifier: "auth1", LinkPublicKey: config.LinkPublicKey{PublicKey: lkPub}}},
		Logging:     &config.Logging{File: filepath.Join(dir, "authority.log"), Level: "ERROR"},
		Debug:       &config.Debug{GenerateOnly: true, MaxPeerConns: &zero, MaxLoopbackConns: &zero},
	}, dir
}

func TestNewUsesOwnKeysAtConfiguredPaths(t *testing.T) {
	cfg, dir := ownKeyConfig(t)
	_, err := New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
	require.FileExists(t, filepath.Join(dir, "id.key"))
	require.FileExists(t, filepath.Join(dir, "id.pub"))
	for _, name := range []string{"identity.private.pem", "identity.public.pem", "link.private.pem", "link.public.pem"} {
		require.NoFileExists(t, filepath.Join(dir, name))
	}
}

func TestNewRejectsAConfiguredLinkKeyNotInAuthorities(t *testing.T) {
	cfg, _ := ownKeyConfig(t)
	other, _, err := kemschemes.ByName("x25519").GenerateKeyPair()
	require.NoError(t, err)
	cfg.Authorities[0].LinkPublicKey = config.LinkPublicKey{PublicKey: other}
	_, err = New(cfg)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrGenerateOnly)
}
