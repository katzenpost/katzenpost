// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// parallel-load drives N concurrent thin clients in pigeonhole
// write-then-read iterations against a running kpclientd. It records
// per-client and per-operation latency to prometheus so throughput-vs-load
// curves, Jain fairness indices, and response-time CDFs can be plotted
// from Grafana.
//
// Single-step example:
//
//	parallel-load -config testdata/thinclient.toml -clients 8 -duration 5m
//
// Sweep example (use this to find the saturation knee):
//
//	parallel-load -config testdata/thinclient.toml \
//	  -sweep 1,2,4,8,16,32 -step 90s
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/katzenpost/katzenpost/tools/chaos/parallelload"
)

func main() {
	configFile := flag.String("config", "client/testdata/thinclient.toml", "thin client TOML config path")
	logLevel := flag.String("log-level", "ERROR", "per-thin-client log level (DEBUG INFO NOTICE WARNING ERROR CRITICAL)")
	clients := flag.Int("clients", 0, "concurrent thin clients (single-step mode)")
	duration := flag.Duration("duration", 0, "single-step duration")
	sweep := flag.String("sweep", "", "comma-separated client counts, e.g. 1,2,4,8,16")
	stepDur := flag.Duration("step", 90*time.Second, "duration per sweep step")
	payload := flag.Int("payload-bytes", 256, "per-iteration message size in bytes")
	metricsAddr := flag.String("metrics", "0.0.0.0:9101", "prometheus listen address; empty disables")
	flag.Parse()

	cfg := parallelload.Config{
		ThinClientConfigPath: *configFile,
		LogLevel:             *logLevel,
		Clients:              *clients,
		Duration:             *duration,
		SweepStepDuration:    *stepDur,
		PayloadBytes:         *payload,
		MetricsAddress:       *metricsAddr,
	}
	if *sweep != "" {
		steps, err := parseSweep(*sweep)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		cfg.SweepSteps = steps
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		fmt.Fprintf(os.Stderr, "parallel-load: caught %s, shutting down\n", s)
		cancel()
	}()

	if err := parallelload.Run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseSweep(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("parallel-load: invalid sweep step %q: %w", p, err)
		}
		if n <= 0 {
			return nil, fmt.Errorf("parallel-load: sweep step must be > 0, got %d", n)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("parallel-load: -sweep is empty")
	}
	return out, nil
}
