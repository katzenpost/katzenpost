// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package chaos

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Runtime parameters that may need to be overridden in unusual
// environments (e.g. when the docker socket path differs from podman's
// default rootless location).
type Runtime struct {
	// Docker is the runtime binary (`docker` or `podman`). The apply
	// tool also accepts the same auto-detection the Makefile uses.
	Docker string
	// PumbaImage is the fully qualified image reference for pumba.
	PumbaImage string
	// TcImage is the image pumba uses to run tc inside the target's
	// network namespace; must include the iproute2 binary.
	TcImage string
	// SocketMount is the -v argument that maps the docker / podman
	// API socket into the pumba container. Empty means: derive it
	// from Docker.
	SocketMount string
}

// DefaultRuntime returns sensible defaults for a podman or docker host.
// If the caller's environment uses podman, $XDG_RUNTIME_DIR is honored
// for the rootless socket path; otherwise the standard
// /var/run/docker.sock is used.
func DefaultRuntime() Runtime {
	docker := "podman"
	if _, err := exec.LookPath("podman"); err != nil {
		docker = "docker"
	}
	rt := Runtime{
		Docker:     docker,
		PumbaImage: "docker.io/gaiaadm/pumba:latest",
		TcImage:    "docker.io/gaiadocker/iproute2",
	}
	rt.SocketMount = defaultSocketMount(docker)
	return rt
}

func defaultSocketMount(docker string) string {
	if docker == "podman" {
		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg == "" {
			xdg = "/run/user/0"
		}
		return fmt.Sprintf("%s/podman/podman.sock:/var/run/docker.sock", xdg)
	}
	return "/var/run/docker.sock:/var/run/docker.sock"
}

// LaneCommand is one pumba sidecar invocation that the apply tool will
// run. The Name is the container_name pumba's sidecar runs under, so
// the family-wide `make pumba-stop` recipe finds them via the
// `katzenpost_pumba_` prefix.
type LaneCommand struct {
	Name string
	Args []string
}

// Plan returns one LaneCommand per chaos primitive on each non-empty
// host. The ordering is deterministic: hosts sorted alphabetically,
// and per-host primitives in a fixed order (pause, delay, loss,
// corrupt). pause-only hosts skip the netem primitives even if
// declared, so the sidecar tc invocations never race the freeze.
func Plan(cfg *Config, rt Runtime) []LaneCommand {
	if cfg == nil {
		return nil
	}
	duration := cfg.Duration
	if duration == "" {
		duration = DefaultDuration
	}
	var plan []LaneCommand
	for _, host := range cfg.SortedHosts() {
		hc := cfg.Hosts[host]
		if hc.PauseForSec > 0 {
			plan = append(plan, pauseLane(host, hc, rt))
			continue
		}
		if hc.LatencyMs > 0 || hc.JitterMs > 0 {
			plan = append(plan, delayLane(host, hc, rt, duration))
		}
		if hc.LossPct > 0 {
			plan = append(plan, lossLane(host, hc, rt, duration))
		}
		if hc.CorruptPct > 0 {
			plan = append(plan, corruptLane(host, hc, rt, duration))
		}
	}
	return plan
}

func laneCommonArgs(rt Runtime, name string) []string {
	return []string{
		"run", "-d", "--rm",
		"--name", name,
		"-v", rt.SocketMount,
		rt.PumbaImage,
		"--log-level", "info",
	}
}

func pauseLane(host string, hc HostChaos, rt Runtime) LaneCommand {
	name := pumbaContainerName(host, "pause")
	args := laneCommonArgs(rt, name)
	args = append(args,
		"pause",
		"--duration", fmt.Sprintf("%ds", hc.PauseForSec),
		host,
	)
	return LaneCommand{Name: name, Args: args}
}

func delayLane(host string, hc HostChaos, rt Runtime, duration string) LaneCommand {
	name := pumbaContainerName(host, "delay")
	distribution := hc.Distribution
	if distribution == "" {
		distribution = "normal"
	}
	args := laneCommonArgs(rt, name)
	args = append(args,
		"netem", "--duration", duration, "--tc-image", rt.TcImage,
		"delay",
		"--time", fmt.Sprintf("%d", hc.LatencyMs),
		"--jitter", fmt.Sprintf("%d", hc.JitterMs),
		"--distribution", distribution,
	)
	if hc.CorrelationPct > 0 {
		args = append(args, "--correlation", fmt.Sprintf("%d", hc.CorrelationPct))
	}
	args = append(args, host)
	return LaneCommand{Name: name, Args: args}
}

func lossLane(host string, hc HostChaos, rt Runtime, duration string) LaneCommand {
	name := pumbaContainerName(host, "loss")
	args := laneCommonArgs(rt, name)
	args = append(args,
		"netem", "--duration", duration, "--tc-image", rt.TcImage,
		"loss",
		"--percent", fmt.Sprintf("%g", hc.LossPct),
	)
	if hc.LossCorrelationPct > 0 {
		args = append(args, "--correlation", fmt.Sprintf("%d", hc.LossCorrelationPct))
	}
	args = append(args, host)
	return LaneCommand{Name: name, Args: args}
}

func corruptLane(host string, hc HostChaos, rt Runtime, duration string) LaneCommand {
	name := pumbaContainerName(host, "corrupt")
	args := laneCommonArgs(rt, name)
	args = append(args,
		"netem", "--duration", duration, "--tc-image", rt.TcImage,
		"corrupt",
		"--percent", fmt.Sprintf("%g", hc.CorruptPct),
		host,
	)
	return LaneCommand{Name: name, Args: args}
}

// pumbaContainerName returns the container name for a chaos lane. The
// `katzenpost_pumba_` prefix matches the Makefile's pumba-stop recipe
// which tears down every container in this family in one step.
func pumbaContainerName(host, primitive string) string {
	return fmt.Sprintf("katzenpost_pumba_%s_%s", host, primitive)
}

// Apply runs every LaneCommand from Plan against the given runtime.
// Errors from individual lanes are joined and returned together so the
// caller can see every failure rather than only the first.
func Apply(ctx context.Context, cfg *Config, rt Runtime) error {
	plan := Plan(cfg, rt)
	if len(plan) == 0 {
		return nil
	}
	var errs []string
	for _, lane := range plan {
		cmd := exec.CommandContext(ctx, rt.Docker, lane.Args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v: %s", lane.Name, err, strings.TrimSpace(string(out))))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("chaos: %d lanes failed:\n  %s", len(errs), strings.Join(errs, "\n  "))
	}
	return nil
}

// Clear stops and removes every container whose name begins with
// `katzenpost_pumba_`. This mirrors the Makefile pumba-stop recipe and
// is safe to call when no chaos is running.
func Clear(ctx context.Context, rt Runtime) error {
	listCmd := exec.CommandContext(ctx, rt.Docker, "ps", "-a",
		"--filter", "name=^katzenpost_pumba_",
		"--format", "{{.Names}}")
	out, err := listCmd.Output()
	if err != nil {
		return fmt.Errorf("chaos: list pumba containers: %w", err)
	}
	names := strings.Fields(string(out))
	if len(names) == 0 {
		return nil
	}
	for _, n := range names {
		// `stop` first so any in-flight tc qdisc is removed cleanly
		// by pumba's shutdown handler; `rm` mops up the container
		// shell whether or not --rm took.
		_ = exec.CommandContext(ctx, rt.Docker, "stop", n).Run()
		_ = exec.CommandContext(ctx, rt.Docker, "rm", n).Run()
	}
	return nil
}
