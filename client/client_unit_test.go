// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSetGetPollInterval(t *testing.T) {
	c := &Client{}

	require.Equal(t, time.Duration(0), c.GetPollInterval())

	c.SetPollInterval(5 * time.Second)
	require.Equal(t, 5*time.Second, c.GetPollInterval())

	c.SetPollInterval(0)
	require.Equal(t, time.Duration(0), c.GetPollInterval())
}
