// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"

	"github.com/katzenpost/katzenpost/core/genconfig/genconfigtest"
)

func TestEpochDurationWiring(t *testing.T) {
	genconfigtest.CheckEpochWiring(t, "client/client.toml", true, func(path string) error {
		_, err := loadFullConfig(path)
		return err
	})
}
