// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

const fetchPeriodChild = "FETCH_EPOCH_PERIOD_CHILD"

func runFetchPeriodChild(t *testing.T) bool {
	if os.Getenv(fetchPeriodChild) != "" {
		return true
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), fetchPeriodChild+"=1", epochtime.EnvironmentVariable+"=")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return false
}

func metricsAt(period time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		epoch := uint64(time.Since(epochtime.Epoch) / period)
		fmt.Fprintf(w, "katzenpost_node_ready 1\nkatzenpost_node_current_epoch %d\n", epoch)
	}))
}

func writeNodeConfig(t *testing.T, netRoot, name, addr, epochDuration string) {
	dir := filepath.Join(netRoot, name)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	line := ""
	if epochDuration != "" {
		line = fmt.Sprintf("  EpochDuration = %q\n", epochDuration)
	}
	b := fmt.Sprintf("[Server]\n  MetricsAddress = %q\n%s", addr, line)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "katzenpost.toml"), []byte(b), 0o600))
}

func readinessNet(t *testing.T, durations map[string]string) (Config, *cpki.Document) {
	netRoot := t.TempDir()
	var layer []*cpki.MixDescriptor
	for name, d := range durations {
		srv := metricsAt(2 * time.Minute)
		t.Cleanup(srv.Close)
		writeNodeConfig(t, netRoot, name, strings.TrimPrefix(srv.URL, "http://"), d)
		layer = append(layer, &cpki.MixDescriptor{Name: name})
	}
	cfg := Config{
		ConfigFile:   filepath.Join(netRoot, "client", "thinclient.toml"),
		RequireReady: true,
		ReadyTimeout: 3 * time.Second,
	}
	return cfg, &cpki.Document{Topology: [][]*cpki.MixDescriptor{layer}}
}

func TestFetchTakesTheEpochPeriodFromTheNodeConfigs(t *testing.T) {
	if !runFetchPeriodChild(t) {
		return
	}
	logger := logging.MustGetLogger("fetch")

	cfg, doc := readinessNet(t, map[string]string{"mix1": "2m0s", "mix2": "20m0s"})
	require.ErrorContains(t, waitForReady(cfg, logger, doc), "EpochDuration")

	cfg, doc = readinessNet(t, map[string]string{"mix1": "2m0s", "mix2": "2m0s"})
	require.NoError(t, waitForReady(cfg, logger, doc))
	require.Equal(t, 2*time.Minute, epochtime.Period())
}

func TestFetchDefaultsTheEpochPeriodTo20m(t *testing.T) {
	if !runFetchPeriodChild(t) {
		return
	}
	cfg, doc := readinessNet(t, map[string]string{"mix1": ""})
	cfg.ReadyTimeout = time.Second
	require.Error(t, waitForReady(cfg, logging.MustGetLogger("fetch"), doc))
	require.Equal(t, 20*time.Minute, epochtime.Period())
}
