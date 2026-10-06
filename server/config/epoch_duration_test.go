// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/core/epochtime/periodtest"
)

func TestEpochDuration(t *testing.T) {
	periodtest.CheckConfig(t, func(line string) (*time.Duration, error) {
		cfg, err := Load([]byte(serverTOML(t, "  "+line+"\n")))
		if err != nil {
			return nil, err
		}
		return cfg.Server.EpochDuration, nil
	})
}
