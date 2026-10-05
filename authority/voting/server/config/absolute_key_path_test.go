// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFixupAndValidateAcceptsAbsoluteNodeKeyPaths(t *testing.T) {
	f := newFixture(t)
	f.cfg.Mixes[0].IdentityPublicKeyPem = filepath.Join(f.dir, f.cfg.Mixes[0].IdentityPublicKeyPem)
	f.cfg.StorageReplicas[0].IdentityPublicKeyPem = filepath.Join(f.dir, f.cfg.StorageReplicas[0].IdentityPublicKeyPem)
	require.True(t, filepath.IsAbs(f.cfg.Mixes[0].IdentityPublicKeyPem))
	require.NoError(t, f.cfg.FixupAndValidate(false))
}

func TestFixupAndValidateDetectsDuplicateAbsoluteAndRelativeKey(t *testing.T) {
	f := newFixture(t)
	f.cfg.Mixes[1].IdentityPublicKeyPem = filepath.Join(f.dir, f.cfg.Mixes[0].IdentityPublicKeyPem)
	require.Error(t, f.cfg.FixupAndValidate(false))
}
