// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	c, err := LoadFile("testdata/replica.toml", false)
	require.NoError(t, err)

	if c.Logging.Level != "DEBUG" {
		panic("Logging.Level should be DEBUG")
	}
}
