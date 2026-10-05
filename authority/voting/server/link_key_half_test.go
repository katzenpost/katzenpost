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

func TestNewLinkKeyHalf(t *testing.T) {
	scheme := kemschemes.ByName("x25519")
	for _, c := range []string{"public", "private", "both"} {
		t.Run(c, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.Chmod(dir, 0o700))
			privFile := filepath.Join(dir, "link.private.pem")
			pubFile := filepath.Join(dir, "link.public.pem")
			pub, priv, err := scheme.GenerateKeyPair()
			require.NoError(t, err)
			if c == "both" || c == "private" {
				require.NoError(t, kempem.PrivateKeyToFile(privFile, priv))
			}
			if c == "both" || c == "public" {
				require.NoError(t, kempem.PublicKeyToFile(pubFile, pub))
			}
			before := map[string][]byte{}
			for _, f := range []string{privFile, pubFile} {
				if b, err := os.ReadFile(f); err == nil {
					before[f] = b
				}
			}
			zero := 0
			cfg := &config.Config{
				Server: &config.Server{
					Identifier:         "auth1",
					WireKEMScheme:      scheme.Name(),
					PKISignatureScheme: "Ed25519 Sphincs+",
					DataDir:            dir,
				},
				Authorities: []*config.Authority{{Identifier: "auth1", LinkPublicKey: config.LinkPublicKey{PublicKey: pub}}},
				Logging:     &config.Logging{File: filepath.Join(dir, "authority.log"), Level: "ERROR"},
				Debug:       &config.Debug{GenerateOnly: true, MaxPeerConns: &zero, MaxLoopbackConns: &zero},
			}

			require.NotPanics(t, func() { _, err = New(cfg) })

			if c == "both" {
				require.ErrorIs(t, err, ErrGenerateOnly)
			} else {
				require.NotErrorIs(t, err, ErrGenerateOnly)
				require.ErrorContains(t, err, privFile)
				require.ErrorContains(t, err, pubFile)
				require.Len(t, before, 1)
				for _, f := range []string{privFile, pubFile} {
					if _, ok := before[f]; !ok {
						require.NoFileExists(t, f)
					}
				}
			}
			for f, b := range before {
				after, err := os.ReadFile(f)
				require.NoError(t, err)
				require.Equal(t, b, after)
			}
		})
	}
}
