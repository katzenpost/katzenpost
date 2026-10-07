// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"

	"github.com/katzenpost/katzenpost/core/genconfig/genconfigtest"
)

func TestEpochDurationWiring(t *testing.T) {
	genconfigtest.CheckEpochWiring(t, "mix1/katzenpost.toml", true, func(path string) error {
		return runServer(Config{ConfigFile: path, ValidateOnly: true})
	})
}
