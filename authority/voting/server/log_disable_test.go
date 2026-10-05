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

func TestNewWithLoggingDisabledReportsErrors(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	scheme := kemschemes.ByName("x25519")
	pub, priv, err := scheme.GenerateKeyPair()
	require.NoError(t, err)
	require.NoError(t, kempem.PrivateKeyToFile(filepath.Join(dir, "link.private.pem"), priv))
	require.NoError(t, kempem.PublicKeyToFile(filepath.Join(dir, "link.public.pem"), pub))
	other, _, err := scheme.GenerateKeyPair()
	require.NoError(t, err)
	zero := 0
	cfg := &config.Config{
		Server: &config.Server{
			Identifier:         "auth1",
			WireKEMScheme:      "x25519",
			PKISignatureScheme: "Ed25519 Sphincs+",
			DataDir:            dir,
		},
		Authorities: []*config.Authority{{Identifier: "auth1", LinkPublicKey: config.LinkPublicKey{PublicKey: other}}},
		Logging:     &config.Logging{Disable: true, Level: "ERROR"},
		Debug:       &config.Debug{GenerateOnly: true, MaxPeerConns: &zero, MaxLoopbackConns: &zero},
	}
	require.NotPanics(t, func() {
		_, err = New(cfg)
	})
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrGenerateOnly)
}
