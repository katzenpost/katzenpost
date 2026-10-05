// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/replica/config"
)

func TestReplicaLinkKeyHalf(t *testing.T) {
	scheme := schemes.ByName("xwing")
	for _, c := range []string{"public", "private", "both", "none"} {
		t.Run(c, func(t *testing.T) {
			dir := t.TempDir()
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
			s := &Server{cfg: &config.Config{
				DataDir:       dir,
				WireKEMScheme: scheme.Name(),
				Logging:       &config.Logging{File: filepath.Join(dir, "replica.log"), Level: "ERROR"},
			}}
			require.NoError(t, s.initLogging())

			require.NotPanics(t, func() { err = s.initLinkKeys() })

			switch c {
			case "both", "none":
				require.NoError(t, err)
				got, err := kempem.FromPublicPEMFile(pubFile, scheme)
				require.NoError(t, err)
				require.True(t, got.Equal(s.linkKey.Public()))
				if c == "both" {
					require.True(t, pub.Equal(got))
				}
			default:
				require.ErrorContains(t, err, privFile)
				require.ErrorContains(t, err, pubFile)
				require.Nil(t, s.linkKey)
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
