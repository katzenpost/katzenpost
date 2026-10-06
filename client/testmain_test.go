// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/katzenpost/katzenpost/core/genconfig/genconfigtest"
)

var testClientTOML string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "client-test-network")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := genconfigtest.Generate(dir, ""); err != nil {
		os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	testClientTOML = filepath.Join(dir, "client", "client.toml")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
