// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewReloadsOwnIdentityFromConfiguredPaths(t *testing.T) {
	cfg, dir := ownKeyConfig(t)
	_, err := New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
	first, err := os.ReadFile(filepath.Join(dir, "id.pub"))
	require.NoError(t, err)

	_, err = New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
	second, err := os.ReadFile(filepath.Join(dir, "id.pub"))
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestNewRejectsHalfAConfiguredIdentityPair(t *testing.T) {
	cfg, dir := ownKeyConfig(t)
	_, err := New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
	require.NoError(t, os.Remove(filepath.Join(dir, "id.pub")))

	_, err = New(cfg)
	require.ErrorContains(t, err, filepath.Join(dir, "id.key"))
	require.ErrorContains(t, err, "must either both exist or not exist")
}

func TestNewRejectsAnUnwritableConfiguredIdentityPath(t *testing.T) {
	cfg, _ := ownKeyConfig(t)
	cfg.Server.IdentityPrivateKeyFile = filepath.Join("absent", "id.key")
	_, err := New(cfg)
	require.ErrorContains(t, err, filepath.Join(cfg.Server.DataDir, "absent", "id.key"))
}
