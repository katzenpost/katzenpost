// SPDX-License-Identifier: AGPL-3.0-only

package genconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestComposePullPolicyIsMissing(t *testing.T) {
	dir := t.TempDir()
	cfg := networkConfig(t, dir, "", nil)
	cfg.NoMetrics = false
	cfg.PyroscopeDirauth = true
	require.NoError(t, RunGenConfig(cfg))
	b, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	require.NoError(t, err)
	var compose struct {
		Services map[string]struct {
			PullPolicy string `yaml:"pull_policy"`
		}
	}
	require.NoError(t, yaml.Unmarshal(b, &compose))
	for _, name := range []string{"metrics", "grafana", "pyroscope"} {
		require.Equal(t, "missing", compose.Services[name].PullPolicy, name)
	}
}
