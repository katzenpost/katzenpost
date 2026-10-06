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
	"gopkg.in/yaml.v3"
)

func genNetwork(t *testing.T, epochDuration string) (string, error) {
	return genNetworkWith(t, epochDuration, nil)
}

func genNetworkWith(t *testing.T, epochDuration string, nodeVersions map[string]string) (string, error) {
	dir := t.TempDir()
	return dir, RunGenConfig(Config{
		NodeVersions:             nodeVersions,
		NrLayers:                 NrLayers,
		NrNodes:                  NrNodes,
		NrGateways:               NrGateways,
		NrServiceNodes:           NrServiceNodes,
		NrStorageNodes:           NrStorageNodes,
		Voting:                   true,
		NrVoting:                 NrAuthorities,
		BaseDir:                  t.TempDir(),
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

func composeEnvironment(t *testing.T, dir string) map[string][]string {
	b, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	require.NoError(t, err)
	var compose struct {
		Services map[string]struct {
			Environment []string
		}
	}
	require.NoError(t, yaml.Unmarshal(b, &compose))
	env := map[string][]string{}
	for name, svc := range compose.Services {
		env[name] = svc.Environment
	}
	return env
}

func TestComposeExportsEpochDurationOnlyToOlderReleases(t *testing.T) {
	older := map[string]bool{"auth2": true, "replica1": true, "mix3": true}
	dir, err := genNetworkWith(t, "2m", map[string]string{
		"auth2": "v0.0.104", "replica1": "v0.0.103", "mix3": "v0.0.104",
		"mix1": "current", "auth1": "current",
	})
	require.NoError(t, err)
	env := composeEnvironment(t, dir)
	require.Contains(t, env, "kpclientd")
	for name, vars := range env {
		var exported []string
		for _, v := range vars {
			if strings.HasPrefix(v, "KATZENPOST_EPOCH_DURATION=") {
				exported = append(exported, v)
			}
		}
		if older[name] {
			require.Equal(t, []string{"KATZENPOST_EPOCH_DURATION=2m0s"}, exported, name)
		} else {
			require.Empty(t, exported, name)
		}
	}
	for name, d := range generatedEpochDurations(t, dir) {
		if filepath.Base(name) != "thinclient.toml" {
			require.Equal(t, 2*time.Minute, *d, name)
		}
	}
}

func TestComposeExportsNoEpochDurationWhenEveryNodeRunsThisBuild(t *testing.T) {
	dir, err := genNetwork(t, "2m")
	require.NoError(t, err)
	for name, vars := range composeEnvironment(t, dir) {
		for _, v := range vars {
			require.False(t, strings.HasPrefix(v, "KATZENPOST_EPOCH_DURATION="), name)
		}
	}
}

func TestGenConfigRefusesNodeVersionsItCannotPlace(t *testing.T) {
	for _, versions := range []map[string]string{
		{"auth2": "main"},
		{"auth2": "d02de7a54"},
		{"auth2": "v0.0"},
		{"auth9": "v0.0.104"},
	} {
		_, err := genNetworkWith(t, "2m", versions)
		require.Error(t, err, versions)
	}
}
