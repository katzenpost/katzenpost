// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// apply-chaos reads a per-host chaos YAML and launches one pumba
// sidecar container per primitive on each non-empty host. The sidecar
// containers carry the `katzenpost_pumba_` prefix so the existing
// `make pumba-stop` target cleans them all up at once.
//
// Example:
//
//	apply-chaos -f experiments/asymmetric.yaml
//
// where experiments/asymmetric.yaml looks like:
//
//	duration: 3m
//	hosts:
//	  mix1: { latency_ms: 25, jitter_ms: 10 }
//	  mix2: { latency_ms: 60, jitter_ms: 20 }
//	  mix3: { latency_ms: 130, jitter_ms: 30 }
//	  replica1: { loss_pct: 0.5 }
//	  auth2: { latency_ms: 80, jitter_ms: 20 }
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/katzenpost/katzenpost/tools/chaos"
)

func main() {
	yamlPath := flag.String("f", "", "path to chaos YAML")
	dryRun := flag.Bool("dry-run", false, "print the pumba commands but do not run them")
	docker := flag.String("docker", "", "container runtime binary; empty auto-detects podman or docker")
	flag.Parse()

	if *yamlPath == "" {
		fmt.Fprintln(os.Stderr, "apply-chaos: -f <chaos.yaml> is required")
		os.Exit(2)
	}

	cfg, err := chaos.LoadFile(*yamlPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	rt := chaos.DefaultRuntime()
	if *docker != "" {
		rt.Docker = *docker
	}

	if *dryRun {
		for _, lane := range chaos.Plan(cfg, rt) {
			fmt.Printf("%s %s\n", rt.Docker, joinArgs(lane.Args))
		}
		return
	}

	if err := chaos.Apply(context.Background(), cfg, rt); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("apply-chaos: %d lanes started\n", len(chaos.Plan(cfg, rt)))
}

// joinArgs renders a command-line that a human can paste back into a
// terminal. Quoting is conservative: every argument with a space or
// shell metachar gets single-quoted.
func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += shellQuote(a)
	}
	return out
}

func shellQuote(s string) string {
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '"' || r == '\'' || r == '$' || r == '|' || r == '&' || r == ';' || r == '*' || r == '?' || r == '<' || r == '>' || r == '(' || r == ')' || r == '[' || r == ']' || r == '{' || r == '}' || r == '\\' {
			return "'" + s + "'"
		}
	}
	return s
}
