// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServerOwnKeysReloadHelper(t *testing.T) {
	dir := os.Getenv("KP_OWN_KEY_DIR")
	if dir == "" {
		t.Skip()
	}
	cfg, _ := ownKeyServerConfig(t)
	cfg.Server.DataDir = dir
	cfg.Server.IdentityPublicKeyFile = filepath.Join(dir, "id.pub")
	cfg.Server.LinkPublicKeyFile = filepath.Join(dir, "link.pub")
	cfg.Logging.File = filepath.Join(dir, "server.log")
	_, err := New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
}

func runOwnKeysReload(t *testing.T, dir string) map[string][]byte {
	cmd := exec.Command(os.Args[0], "-test.run=^TestServerOwnKeysReloadHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "KP_OWN_KEY_DIR="+dir)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	keys := make(map[string][]byte)
	for _, name := range []string{"id.key", "id.pub", "link.key", "link.pub"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		keys[name] = b
	}
	return keys
}

func TestServerReloadsOwnKeysFromConfiguredPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("DataDir's 0700 permission check cannot pass on windows")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	first := runOwnKeysReload(t, dir)
	require.Equal(t, first, runOwnKeysReload(t, dir))
	for _, name := range []string{"identity.private.pem", "identity.public.pem", "link.private.pem", "link.public.pem"} {
		require.NoFileExists(t, filepath.Join(dir, name))
	}
}
