// SPDX-License-Identifier: AGPL-3.0-only

package genconfig

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func genForCover(t *testing.T, cover bool) (string, string) {
	t.Helper()
	out := t.TempDir()
	base := t.TempDir()
	cfg := Config{
		NrLayers:                 3,
		NrNodes:                  3,
		NrGateways:               1,
		NrServiceNodes:           1,
		NrStorageNodes:           2,
		Voting:                   true,
		NrVoting:                 3,
		BaseDir:                  base,
		BasePort:                 35000,
		BindAddr:                 "127.0.0.1",
		OutDir:                   out,
		DockerImage:              "katzenpost-alpine_base",
		LogLevel:                 "DEBUG",
		Wirekem:                  "xwing",
		Nike:                     "x25519",
		UserForwardPayloadLength: 2000,
		PkiSignatureScheme:       "Ed25519",
		Mu:                       0.005,
		LP:                       0.001,
		LL:                       0.0005,
		LM:                       0.0005,
		LR:                       0.005,
		NoMetrics:                true,
		Cover:                    cover,
	}
	require.NoError(t, RunGenConfig(cfg))
	b, err := os.ReadFile(filepath.Join(out, "docker-compose.yml"))
	require.NoError(t, err)
	return string(b), base
}

func TestCoverWritesGOCOVERDIRPerService(t *testing.T) {
	compose, base := genForCover(t, true)
	re := regexp.MustCompile(`GOCOVERDIR=` + regexp.QuoteMeta(base+"/coverage/") + `([a-z0-9]+)`)
	m := re.FindAllStringSubmatch(compose, -1)
	require.NotEmpty(t, m)
	seen := map[string]bool{}
	for _, x := range m {
		require.False(t, seen[x[1]], "service %s twice", x[1])
		seen[x[1]] = true
	}
	for _, want := range []string{"auth1", "mix1", "gateway1", "servicenode1", "replica1", "kpclientd"} {
		require.True(t, seen[want], "no GOCOVERDIR for %s", want)
	}
}

func TestCoverCreatesHostDirs(t *testing.T) {
	out := t.TempDir()
	s := &Katzenpost{OutDir: out, BaseDir: "/conf", Cover: true}
	require.Equal(t, "/conf/coverage/mix1", s.coverDir("mix1"))
	fi, err := os.Stat(filepath.Join(out, "coverage", "mix1"))
	require.NoError(t, err)
	require.True(t, fi.IsDir())
}

func TestNoCoverByDefault(t *testing.T) {
	compose, _ := genForCover(t, false)
	require.False(t, strings.Contains(compose, "GOCOVERDIR"))
	s := &Katzenpost{OutDir: t.TempDir(), BaseDir: "/conf"}
	require.Equal(t, "", s.coverDir("mix1"))
}
