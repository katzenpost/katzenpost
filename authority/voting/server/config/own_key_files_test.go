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
	require.Equal(t, filepath.Join("/data", "identity.private.pem"), s.IdentityPrivateKeyPath())
	require.Equal(t, filepath.Join("/data", "identity.public.pem"), s.IdentityPublicKeyPath())
	require.Equal(t, filepath.Join("/data", "link.private.pem"), s.LinkPrivateKeyPath())
	require.Equal(t, filepath.Join("/data", "link.public.pem"), s.LinkPublicKeyPath())
}

func TestOwnKeyPathsConfigured(t *testing.T) {
	dir := t.TempDir()
	idPub := filepath.Join(dir, "id.pub")
	linkPub := filepath.Join(dir, "link.pub")
	s := &Server{
		DataDir:                "/data",
		IdentityPrivateKeyFile: "keys/id.key",
		IdentityPublicKeyFile:  idPub,
		LinkPrivateKeyFile:     "keys/link.key",
		LinkPublicKeyFile:      linkPub,
	}
	require.Equal(t, filepath.Join("/data", "keys/id.key"), s.IdentityPrivateKeyPath())
	require.Equal(t, idPub, s.IdentityPublicKeyPath())
	require.Equal(t, filepath.Join("/data", "keys/link.key"), s.LinkPrivateKeyPath())
	require.Equal(t, linkPub, s.LinkPublicKeyPath())
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
