// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime/periodtest"
)

func TestEpochDuration(t *testing.T) {
	b, err := os.ReadFile(TestClientTOML)
	require.NoError(t, err)
	b = regexp.MustCompile(`(?m)^EpochDuration = .*\n`).ReplaceAll(b, nil)
	periodtest.CheckConfig(t, func(line string) (*time.Duration, error) {
		cfg, err := Load([]byte(line + "\n" + string(b)))
		if err != nil {
			return nil, err
		}
		return cfg.EpochDuration, nil
	})
}
