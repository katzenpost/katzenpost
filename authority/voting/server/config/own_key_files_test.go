// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOwnKeyPathsDefault(t *testing.T) {
	s := &Server{DataDir: "/data"}
	require.Equal(t, "/data/identity.private.pem", s.IdentityPrivateKeyPath())
	require.Equal(t, "/data/identity.public.pem", s.IdentityPublicKeyPath())
	require.Equal(t, "/data/link.private.pem", s.LinkPrivateKeyPath())
	require.Equal(t, "/data/link.public.pem", s.LinkPublicKeyPath())
}

func TestOwnKeyPathsConfigured(t *testing.T) {
	s := &Server{
		DataDir:                "/data",
		IdentityPrivateKeyFile: "keys/id.key",
		IdentityPublicKeyFile:  "/etc/auth/id.pub",
		LinkPrivateKeyFile:     "keys/link.key",
		LinkPublicKeyFile:      "/etc/auth/link.pub",
	}
	require.Equal(t, "/data/keys/id.key", s.IdentityPrivateKeyPath())
	require.Equal(t, "/etc/auth/id.pub", s.IdentityPublicKeyPath())
	require.Equal(t, "/data/keys/link.key", s.LinkPrivateKeyPath())
	require.Equal(t, "/etc/auth/link.pub", s.LinkPublicKeyPath())
}

func TestFixupAndValidateUsesConfiguredIdentityKeyFile(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, os.Rename(filepath.Join(f.dir, "identity.public.pem"), filepath.Join(f.dir, "auth1.id.pub")))
	require.Error(t, f.cfg.FixupAndValidate(false))
	f.cfg.Server.IdentityPublicKeyFile = "auth1.id.pub"
	require.NoError(t, f.cfg.FixupAndValidate(false))
}

func TestFixupAndValidateRejectsAMissingConfiguredIdentityKeyFile(t *testing.T) {
	f := newFixture(t)
	f.cfg.Server.IdentityPublicKeyFile = filepath.Join(f.dir, "absent.pub")
	require.Error(t, f.cfg.FixupAndValidate(false))
}
