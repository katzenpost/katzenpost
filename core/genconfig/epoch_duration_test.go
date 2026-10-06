// SPDX-License-Identifier: AGPL-3.0-only

package genconfig

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

func genNetwork(t *testing.T, epochDuration string) (string, error) {
	dir := t.TempDir()
	return dir, RunGenConfig(Config{
		NrLayers:                 NrLayers,
		NrNodes:                  NrNodes,
		NrGateways:               NrGateways,
		NrServiceNodes:           NrServiceNodes,
		NrStorageNodes:           NrStorageNodes,
		Voting:                   true,
		NrVoting:                 NrAuthorities,
		BaseDir:                  "/conf",
		OutDir:                   dir,
		BasePort:                 30000,
		BindAddr:                 BindAddr,
		LogLevel:                 DebugLogLevel,
		Wirekem:                  "xwing",
		Nike:                     "x25519",
		PkiSignatureScheme:       testSchemeName,
		UserForwardPayloadLength: 2000,
		EpochDuration:            epochDuration,
		NoMetrics:                true,
		Mu:                       0.005,
		LP:                       0.001,
		LL:                       0.0005,
		LM:                       0.2,
		LR:                       0.0005,
	})
}

func generatedEpochDurations(t *testing.T, dir string) map[string]*time.Duration {
	got := map[string]*time.Duration{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".toml") {
			return err
		}
		var c struct {
			EpochDuration *time.Duration
			Server        struct{ EpochDuration *time.Duration }
		}
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		_, err = toml.Decode(string(b), &c)
		require.NoError(t, err, p)
		rel, _ := filepath.Rel(dir, p)
		got[rel] = c.EpochDuration
		if c.Server.EpochDuration != nil {
			got[rel] = c.Server.EpochDuration
		}
		return nil
	})
	require.NoError(t, err)
	return got
}

func TestGenConfigWritesEpochDuration(t *testing.T) {
	for _, c := range []struct {
		flag string
		want time.Duration
	}{
		{"3m", 3 * time.Minute},
		{"", 20 * time.Minute},
	} {
		dir, err := genNetwork(t, c.flag)
		require.NoError(t, err)
		got := generatedEpochDurations(t, dir)
		require.Len(t, got, 3+1+1+NrNodes+NrGateways+2*NrServiceNodes+NrStorageNodes)
		for name, d := range got {
			if filepath.Base(name) == "thinclient.toml" {
				require.Nil(t, d, name)
				continue
			}
			require.NotNil(t, d, name)
			require.Equal(t, c.want, *d, name)
		}
	}
}

func TestGenConfigRefusesAnInvalidEpochDuration(t *testing.T) {
	for _, flag := range []string{"90s", "2m0.5s", "soon"} {
		_, err := genNetwork(t, flag)
		require.Error(t, err, flag)
	}
}
