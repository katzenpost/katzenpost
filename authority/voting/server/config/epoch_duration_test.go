// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/core/epochtime/periodtest"
)

func TestEpochDuration(t *testing.T) {
	f := newFixture(t)
	periodtest.CheckConfig(t, func(line string) (*time.Duration, error) {
		cfg, err := Load([]byte(strings.Replace(f.tomlText(), "[Server]\n", "[Server]\n"+line+"\n", 1)), false)
		if err != nil {
			return nil, err
		}
		return cfg.Server.EpochDuration, nil
	})
}
