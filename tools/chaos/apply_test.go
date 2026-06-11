// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package chaos

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlanProducesOneLanePerPrimitivePerHost(t *testing.T) {
	rt := Runtime{
		Docker:      "podman",
		PumbaImage:  "docker.io/gaiaadm/pumba:latest",
		TcImage:     "docker.io/gaiadocker/iproute2",
		SocketMount: "/tmp/socket:/var/run/docker.sock",
	}
	cfg := &Config{
		Duration: "1m",
		Hosts: map[string]HostChaos{
			"mix1": {LatencyMs: 100, JitterMs: 30},
			"replica1": {
				LatencyMs:  50,
				LossPct:    0.5,
				CorruptPct: 0.01,
			},
			"mix2":  {PauseForSec: 30},
			"auth1": {LossPct: 1.0},
			"mix3":  {}, // empty; ignored
			"replica2": {
				// pause wins over netem on the same host
				PauseForSec: 10,
				LatencyMs:   200,
			},
		},
	}
	plan := Plan(cfg, rt)

	// Expected lanes in deterministic alphabetic-host order:
	//   auth1 loss
	//   mix1  delay
	//   mix2  pause
	//   replica1 delay, loss, corrupt
	//   replica2 pause (LatencyMs ignored because PauseForSec dominates)
	wantNames := []string{
		"katzenpost_pumba_auth1_loss",
		"katzenpost_pumba_mix1_delay",
		"katzenpost_pumba_mix2_pause",
		"katzenpost_pumba_replica1_delay",
		"katzenpost_pumba_replica1_loss",
		"katzenpost_pumba_replica1_corrupt",
		"katzenpost_pumba_replica2_pause",
	}
	gotNames := make([]string, 0, len(plan))
	for _, lane := range plan {
		gotNames = append(gotNames, lane.Name)
	}
	require.Equal(t, wantNames, gotNames)
}

func TestPlanDelayLaneIncludesCorrelation(t *testing.T) {
	rt := Runtime{
		Docker:      "podman",
		PumbaImage:  "p",
		TcImage:     "tc",
		SocketMount: "s",
	}
	cfg := &Config{Hosts: map[string]HostChaos{"mix1": {LatencyMs: 50, JitterMs: 20, CorrelationPct: 25}}}
	plan := Plan(cfg, rt)
	require.Len(t, plan, 1)
	joined := strings.Join(plan[0].Args, " ")
	require.Contains(t, joined, "--correlation 25")
}

func TestPlanLossLanePercent(t *testing.T) {
	rt := Runtime{
		Docker:      "podman",
		PumbaImage:  "p",
		TcImage:     "tc",
		SocketMount: "s",
	}
	cfg := &Config{Hosts: map[string]HostChaos{"gateway1": {LossPct: 0.25, LossCorrelationPct: 10}}}
	plan := Plan(cfg, rt)
	require.Len(t, plan, 1)
	joined := strings.Join(plan[0].Args, " ")
	require.Contains(t, joined, "loss --percent 0.25")
	require.Contains(t, joined, "--correlation 10")
}

func TestPlanDefaultsToFiveMinutes(t *testing.T) {
	rt := Runtime{Docker: "podman", PumbaImage: "p", TcImage: "tc", SocketMount: "s"}
	cfg := &Config{Hosts: map[string]HostChaos{"mix1": {LatencyMs: 10}}}
	plan := Plan(cfg, rt)
	require.Len(t, plan, 1)
	require.Contains(t, strings.Join(plan[0].Args, " "), "--duration 5m")
}

func TestPlanEmpty(t *testing.T) {
	require.Nil(t, Plan(nil, Runtime{}))
	require.Nil(t, Plan(&Config{}, Runtime{}))
}
