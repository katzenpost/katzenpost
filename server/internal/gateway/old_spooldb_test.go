// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/config"
)

// removeOldSpoolDB runs it against dataDir and returns the log output.
func removeOldSpoolDB(t *testing.T, dataDir string, spoolDB *config.SpoolDB) string {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "gateway.log")
	logBackend, err := log.New(logPath, "INFO", false)
	require.NoError(t, err)
	p := &gateway{log: logBackend.GetLogger("gateway")}
	p.removeOldSpoolDB(&config.Config{
		Server:  &config.Server{DataDir: dataDir},
		Gateway: &config.Gateway{SpoolDB: spoolDB},
	})
	logBackend.Close()
	b, err := os.ReadFile(logPath)
	require.NoError(t, err)
	return string(b)
}

func bolt(path string) *config.SpoolDB {
	return &config.SpoolDB{Backend: config.BackendBolt, Bolt: &config.BoltSpoolDB{SpoolDB: path}}
}

func TestRemoveOldSpoolDB(t *testing.T) {
	t.Run("configured file is removed", func(t *testing.T) {
		dataDir := t.TempDir()
		path := filepath.Join(t.TempDir(), "custom.db")
		other := filepath.Join(dataDir, "spool.db")
		require.NoError(t, os.WriteFile(path, make([]byte, 8192), 0600))
		require.NoError(t, os.WriteFile(other, []byte("x"), 0600))

		out := removeOldSpoolDB(t, dataDir, bolt(path))
		require.NoFileExists(t, path)
		require.FileExists(t, other, "only the configured path is touched")
		require.Contains(t, out, " NOTI ", out)
		require.Contains(t, out, fmt.Sprintf("Removed the old spool file %s (8192 bytes)", path), out)
	})
	t.Run("default path is removed", func(t *testing.T) {
		dataDir := t.TempDir()
		path := filepath.Join(dataDir, "spool.db")
		keep := filepath.Join(dataDir, "external_queue.db")
		require.NoError(t, os.WriteFile(path, make([]byte, 4096), 0600))
		require.NoError(t, os.WriteFile(keep, []byte("x"), 0600))

		out := removeOldSpoolDB(t, dataDir, nil)
		require.NoFileExists(t, path)
		require.FileExists(t, keep, "nothing else in the data dir is touched")
		require.Contains(t, out, fmt.Sprintf("Removed the old spool file %s (4096 bytes)", path), out)
	})
	t.Run("missing file", func(t *testing.T) {
		out := removeOldSpoolDB(t, t.TempDir(), nil)
		require.NotContains(t, out, "spool file", out)
	})
	t.Run("directory is left alone", func(t *testing.T) {
		dataDir := t.TempDir()
		path := filepath.Join(dataDir, "spool.db")
		require.NoError(t, os.Mkdir(path, 0700))
		out := removeOldSpoolDB(t, dataDir, nil)
		require.DirExists(t, path)
		require.NotContains(t, out, "spool file", out)
	})
	t.Run("symlink is left alone", func(t *testing.T) {
		dataDir := t.TempDir()
		target := filepath.Join(dataDir, "target")
		path := filepath.Join(dataDir, "spool.db")
		require.NoError(t, os.WriteFile(target, []byte("x"), 0600))
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		out := removeOldSpoolDB(t, dataDir, nil)
		_, err := os.Lstat(path)
		require.NoError(t, err)
		require.FileExists(t, target)
		require.NotContains(t, out, "spool file", out)
	})
	t.Run("relative configured path is ignored", func(t *testing.T) {
		out := removeOldSpoolDB(t, t.TempDir(), bolt("spool.db"))
		require.NotContains(t, out, "spool file", out)
	})
	t.Run("remove error is a warning", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root can remove from a read-only directory")
		}
		dataDir := t.TempDir()
		path := filepath.Join(dataDir, "spool.db")
		require.NoError(t, os.WriteFile(path, []byte("x"), 0600))
		require.NoError(t, os.Chmod(dataDir, 0500))
		defer os.Chmod(dataDir, 0700)

		out := removeOldSpoolDB(t, dataDir, nil)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Skip("this platform removed the file despite the read-only directory")
		}
		require.Contains(t, out, "WARN", out)
		require.Contains(t, out, "Failed to remove the old spool file "+path, out)
	})
}
