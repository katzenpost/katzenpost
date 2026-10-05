// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadTOMLWithIdentityPublicKeyFile(t *testing.T) {
	names := []string{"mix1", "mix2", "gw1", "svc1", "rep1"}
	rewrite := func(f *fixture, line func(name string) string) string {
		txt := f.tomlText()
		for _, n := range names {
			txt = strings.Replace(txt, `IdentityPublicKeyPem = "`+n+`.pem"`, line(n), 1)
		}
		return txt
	}

	t.Run("relative", func(t *testing.T) {
		f := newFixture(t)
		cfg, err := Load([]byte(rewrite(f, func(n string) string {
			return `IdentityPublicKeyFile = "` + n + `.pem"`
		})), false)
		require.NoError(t, err)
		require.False(t, cfg.DeprecatedIdentityPublicKeyPem())
		require.Equal(t, "mix1.pem", cfg.Mixes[0].KeyFile())
		require.Equal(t, "rep1.pem", cfg.StorageReplicas[0].KeyFile())
	})

	t.Run("absolute from a file", func(t *testing.T) {
		f := newFixture(t)
		txt := rewrite(f, func(n string) string {
			return `IdentityPublicKeyFile = "` + strings.ReplaceAll(filepath.Join(f.dir, n+".pem"), `\`, `\\`) + `"`
		})
		path := filepath.Join(f.dir, "authority.toml")
		require.NoError(t, os.WriteFile(path, []byte(txt), 0o600))
		cfg, err := LoadFile(path, false)
		require.NoError(t, err)
		require.True(t, filepath.IsAbs(cfg.GatewayNodes[0].KeyFile()))
	})

	t.Run("deprecated name", func(t *testing.T) {
		f := newFixture(t)
		cfg, err := Load([]byte(f.tomlText()), false)
		require.NoError(t, err)
		require.True(t, cfg.DeprecatedIdentityPublicKeyPem())
	})

	t.Run("both names differ", func(t *testing.T) {
		f := newFixture(t)
		_, err := Load([]byte(rewrite(f, func(n string) string {
			return `IdentityPublicKeyPem = "` + n + `.pem"` + "\n" + `IdentityPublicKeyFile = "other.pem"`
		})), false)
		require.ErrorContains(t, err, "differ")
	})

	t.Run("duplicate key through the new name", func(t *testing.T) {
		f := newFixture(t)
		_, err := Load([]byte(rewrite(f, func(n string) string {
			if n == "mix2" {
				return `IdentityPublicKeyFile = "mix1.pem"`
			}
			return `IdentityPublicKeyFile = "` + n + `.pem"`
		})), false)
		require.Error(t, err)
	})

	t.Run("missing key file", func(t *testing.T) {
		f := newFixture(t)
		_, err := Load([]byte(rewrite(f, func(n string) string {
			return `IdentityPublicKeyFile = "nope-` + n + `.pem"`
		})), false)
		require.ErrorContains(t, err, "nope-mix1.pem")
	})
}
