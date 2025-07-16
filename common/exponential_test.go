//go:build time_test

// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

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

func NoTestExponentialAverage(t *testing.T) {
	e := NewExpDist()

	averageMsec := 100
	maxMsec := 300

	e.UpdateRate(uint64(averageMsec), uint64(maxMsec))
	e.UpdateConnectionStatus(true)

	numPkts := 100
	base := time.Time{}
	var duration time.Duration
	for i := 0; i < numPkts; i++ {
		then := time.Now()
		<-e.OutCh()
		timeSince := time.Since(then)
		t.Logf("timeSince: %v", timeSince)
		duration += timeSince
		require.Less(t, timeSince, time.Duration(maxMsec+20)*time.Millisecond) // clamping to maxMsec slops over maxMsec < 1ms
	}

	// require that the average over 100 samples be within 2 seconds (100 msec * 100 pkts ~ 10 seconds, meaning this needs to be within 20%
	require.WithinDuration(t, base.Add(duration), base.Add(time.Duration(numPkts)*time.Duration(averageMsec)*time.Millisecond), time.Duration(float64(numPkts)*0.2*float64(averageMsec))*time.Millisecond)
}
