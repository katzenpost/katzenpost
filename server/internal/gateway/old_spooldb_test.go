// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/config"
)

func TestWarnOldSpoolDB(t *testing.T) {
	dataDir := t.TempDir()
	custom := filepath.Join(t.TempDir(), "custom.db")
	bolt := func(path string) *config.SpoolDB {
		return &config.SpoolDB{Backend: config.BackendBolt, Bolt: &config.BoltSpoolDB{SpoolDB: path}}
	}

	for _, tc := range []struct {
		name    string
		spoolDB *config.SpoolDB
		file    string // written before the check
		size    int
		want    string // expected path in the warning; "" means no warning
	}{
		{"no file", nil, "", 0, ""},
		{"empty default file", nil, filepath.Join(dataDir, "spool.db"), 0, ""},
		{"default file", nil, filepath.Join(dataDir, "spool.db"), 4096, filepath.Join(dataDir, "spool.db")},
		{"configured path", bolt(custom), custom, 8192, custom},
		{"configured path missing", bolt(filepath.Join(dataDir, "absent.db")), "", 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			os.Remove(filepath.Join(dataDir, "spool.db"))
			os.Remove(custom)
			if tc.file != "" {
				require.NoError(t, os.WriteFile(tc.file, make([]byte, tc.size), 0600))
			}
			logPath := filepath.Join(t.TempDir(), "gateway.log")
			logBackend, err := log.New(logPath, "INFO", false)
			require.NoError(t, err)
			p := &gateway{log: logBackend.GetLogger("gateway")}
			p.warnOldSpoolDB(&config.Config{
				Server:  &config.Server{DataDir: dataDir},
				Gateway: &config.Gateway{SpoolDB: tc.spoolDB},
			})
			logBackend.Close()

			b, err := os.ReadFile(logPath)
			require.NoError(t, err)
			if tc.want == "" {
				require.NotContains(t, string(b), "spool database", string(b))
				return
			}
			require.Equal(t, 1, strings.Count(string(b), "WARN"), string(b))
			require.Contains(t, string(b), fmt.Sprintf("%s (%d bytes) is no longer read", tc.want, tc.size), string(b))
		})
	}
}
