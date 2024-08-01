//go:build time

// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExponential(t *testing.T) {
	rate := 0.001
	maxDelay := uint64(1000)
	e := NewExpDist()

	e.UpdateRate(uint64(1/rate), maxDelay)
	e.UpdateConnectionStatus(true)

	fired := 0
	failed := 0
	timerDuration := time.Second * 2
	rateTimer := time.NewTimer(timerDuration)

	for i := 0; i < 3; i++ {
		t.Log("before reading from OutCh")
		select {
		case <-e.OutCh():
			fired += 1
			rateTimer.Reset(timerDuration)
		case <-rateTimer.C:
			failed += 1
		}
		t.Log("out")
	}

	require.Equal(t, fired, 3)
	require.Equal(t, failed, 0)
}
