// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

func TestReportEpochsAcrossBoundary(t *testing.T) {
	period := epochtime.Period()
	first := epochtime.Epoch.Add(1000 * period)
	second := first.Add(period)
	a := &attribution{}
	for i := range 4 {
		a.record(observation{cat: catDelivered, at: first.Add(time.Duration(i) * time.Second), ok: true})
	}
	for i := range 4 {
		ok := i == 0
		cat := catLost
		if ok {
			cat = catDelivered
		}
		a.record(observation{cat: cat, at: second.Add(time.Duration(i) * time.Second), ok: ok})
	}
	var buf bytes.Buffer
	a.reportEpochs(&buf)
	out := buf.String()
	require.Contains(t, out, "epoch 1000")
	require.Contains(t, out, "4/4")
	require.Contains(t, out, "epoch 1001")
	require.Contains(t, out, "1/4")
}

func TestReportEpochsSingleEpochIsSilent(t *testing.T) {
	at := epochtime.Epoch.Add(1000 * epochtime.Period())
	a := &attribution{}
	a.record(observation{cat: catDelivered, at: at, ok: true})
	a.record(observation{cat: catLost, at: at.Add(time.Second)})
	var buf bytes.Buffer
	a.reportEpochs(&buf)
	require.Empty(t, buf.String())
}

func TestReportEpochsIgnoresUntimedObservations(t *testing.T) {
	period := epochtime.Period()
	at := epochtime.Epoch.Add(1000 * period)
	a := &attribution{}
	a.record(observation{cat: catDelivered, at: at, ok: true})
	a.record(observation{cat: catLost})
	a.record(observation{cat: catDelivered, ok: true})
	var buf bytes.Buffer
	a.reportEpochs(&buf)
	require.Empty(t, buf.String())

	a.record(observation{cat: catLost, at: at.Add(period)})
	buf.Reset()
	a.reportEpochs(&buf)
	out := buf.String()
	require.Contains(t, out, "epoch 1000  1/1")
	require.Contains(t, out, "epoch 1001  0/1")
	require.Equal(t, 3, strings.Count(out, "\n"))
}
