// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServerOwnKeyPathsDefault(t *testing.T) {
	s := &Server{DataDir: "/data"}
	require.Equal(t, "/data/identity.private.pem", s.IdentityPrivateKeyPath())
	require.Equal(t, "/data/identity.public.pem", s.IdentityPublicKeyPath())
	require.Equal(t, "/data/link.private.pem", s.LinkPrivateKeyPath())
	require.Equal(t, "/data/link.public.pem", s.LinkPublicKeyPath())
}

func TestServerOwnKeyPathsConfigured(t *testing.T) {
	s := &Server{
		DataDir:                "/data",
		IdentityPrivateKeyFile: "keys/id.key",
		IdentityPublicKeyFile:  "/etc/mix/id.pub",
		LinkPrivateKeyFile:     "keys/link.key",
		LinkPublicKeyFile:      "/etc/mix/link.pub",
	}
	require.Equal(t, "/data/keys/id.key", s.IdentityPrivateKeyPath())
	require.Equal(t, "/etc/mix/id.pub", s.IdentityPublicKeyPath())
	require.Equal(t, "/data/keys/link.key", s.LinkPrivateKeyPath())
	require.Equal(t, "/etc/mix/link.pub", s.LinkPublicKeyPath())
}
