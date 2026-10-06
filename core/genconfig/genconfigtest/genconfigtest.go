// SPDX-License-Identifier: AGPL-3.0-only

package genconfigtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/genconfig"
)

const (
	childPath = "GENCONFIGTEST_CHILD_PATH"
	childWant = "GENCONFIGTEST_CHILD_WANT"
)

func Network(t *testing.T, epochDuration string) string {
	t.Helper()
	dir := t.TempDir()
	if err := Generate(dir, epochDuration); err != nil {
		t.Fatal(err)
	}
	return dir
}

func Generate(dir, epochDuration string) error {
	return genconfig.RunGenConfig(genconfig.Config{
		NrLayers:                 genconfig.NrLayers,
		NrNodes:                  genconfig.NrNodes,
		NrGateways:               genconfig.NrGateways,
		NrServiceNodes:           genconfig.NrServiceNodes,
		NrStorageNodes:           genconfig.NrStorageNodes,
		Voting:                   true,
		NrVoting:                 genconfig.NrAuthorities,
		BaseDir:                  dir,
		OutDir:                   dir,
		BasePort:                 30000,
		BindAddr:                 "127.0.0.1",
		LogLevel:                 genconfig.DebugLogLevel,
		Wirekem:                  "xwing",
		Nike:                     "x25519",
		PkiSignatureScheme:       PKIScheme,
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

func CheckEpochWiring(t *testing.T, rel string, observePeriod bool, run func(path string) error) {
	t.Helper()
	if path := os.Getenv(childPath); path != "" {
		if err := run(path); err != nil {
			t.Fatal(err)
		}
		if want, _ := time.ParseDuration(os.Getenv(childWant)); observePeriod && epochtime.Period() != want {
			t.Fatalf("period %v, want %v", epochtime.Period(), want)
		}
		return
	}
	dir := Network(t, "3m")
	path := filepath.Join(dir, rel)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(filepath.Dir(path), "absent-"+filepath.Base(path))
	stripped := regexp.MustCompile(`(?m)^\s*EpochDuration = .*\n`).ReplaceAll(b, nil)
	if err := os.WriteFile(absent, stripped, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, path, env, want string
		fails, warns          bool
	}{
		{"config", path, "", "3m", false, false},
		{"config and equal environment", path, "3m", "3m", false, false},
		{"config and different environment", path, "4m", "", true, false},
		{"environment only", absent, "2m", "2m", false, true},
		{"neither", absent, "", "20m", false, false},
	} {
		cmd := exec.Command(os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.count=1")
		cmd.Env = append(os.Environ(), childPath+"="+c.path, childWant+"="+c.want, epochtime.EnvironmentVariable+"="+c.env)
		out, err := cmd.CombinedOutput()
		switch {
		case c.fails && err == nil:
			t.Errorf("%s: started, want a refusal\n%s", c.name, out)
		case c.fails && !strings.Contains(string(out), epochtime.EnvironmentVariable):
			t.Errorf("%s: refusal does not name %s\n%s", c.name, epochtime.EnvironmentVariable, out)
		case !c.fails && err != nil:
			t.Errorf("%s: %v\n%s", c.name, err, out)
		case c.warns != strings.Contains(string(out), "deprecated"):
			t.Errorf("%s: deprecation warning %v, want %v\n%s", c.name, !c.warns, c.warns, out)
		}
	}
}
