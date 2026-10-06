// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/genconfig/genconfigtest"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "client-config-test-network")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := genconfigtest.Generate(dir, ""); err != nil {
		os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	config.TestClientTOML = filepath.Join(dir, "client", "client.toml")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
