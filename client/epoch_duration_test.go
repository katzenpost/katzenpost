// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/genconfig/genconfigtest"
	"github.com/katzenpost/katzenpost/core/log"
)

func TestNewConfiguresTheEpochDuration(t *testing.T) {
	genconfigtest.CheckEpochWiring(t, "client/client.toml", true, func(path string) error {
		cfg, err := config.LoadFile(path)
		if err != nil {
			return err
		}
		logBackend, err := log.New("", "ERROR", false)
		if err != nil {
			return err
		}
		_, err = New(cfg, logBackend)
		return err
	})
}
