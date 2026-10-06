// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"

	"github.com/katzenpost/katzenpost/core/genconfig/genconfigtest"
)

func TestEpochDurationWiring(t *testing.T) {
	genconfigtest.CheckEpochWiring(t, "auth1/authority.toml", true, func(path string) error {
		return runAuthority(Config{ConfigFile: path, ValidateOnly: true})
	})
}
