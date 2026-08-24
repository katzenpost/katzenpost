// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServerOwnKeyPathsDefault(t *testing.T) {
	s := &Server{DataDir: "/data"}
	require.Equal(t, filepath.Join("/data", "identity.private.pem"), s.IdentityPrivateKeyPath())
	require.Equal(t, filepath.Join("/data", "identity.public.pem"), s.IdentityPublicKeyPath())
	require.Equal(t, filepath.Join("/data", "link.private.pem"), s.LinkPrivateKeyPath())
	require.Equal(t, filepath.Join("/data", "link.public.pem"), s.LinkPublicKeyPath())
}

func TestServerOwnKeyPathsConfigured(t *testing.T) {
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
