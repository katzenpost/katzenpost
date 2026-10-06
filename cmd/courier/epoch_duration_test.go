// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"

	"github.com/katzenpost/katzenpost/core/genconfig/genconfigtest"
)

func TestEpochDurationWiring(t *testing.T) {
	genconfigtest.CheckEpochWiring(t, "servicenode1/courier/courier.toml", false, func(path string) error {
		runCourier(courierConfig{configFile: path, validateOnly: true})
		return nil
	})
}
