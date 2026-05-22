// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// cp-bench drives an end-to-end pigeonhole-cp throughput benchmark.
// One run uploads a random payload of the requested size via the
// copy command and measures wall-clock bytes/sec from Alice's first
// chunk write to Bob's last reconstructed byte. The intended use is
// to compare Sphinx geometries: larger UserForwardPayloadLength
// fewer CTIDH ops per useful byte, so throughput in bytes/sec
// scales with the chunk size.
//
// Example single-payload run:
//
//	cp-bench -config testdata/thinclient.toml -payload 65536
//
// Example sweep (warm-up + three sizes):
//
//	cp-bench -config testdata/thinclient.toml \
//	  -sweep 4096,16384,65536,262144 -metrics 0.0.0.0:9102
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

	"github.com/katzenpost/katzenpost/chaos/cpbench"
)

func main() {
	configFile := flag.String("config", "client/testdata/thinclient.toml", "thin client TOML config path")
	logLevel := flag.String("log-level", "ERROR", "per-thin-client log level (DEBUG INFO NOTICE WARNING ERROR CRITICAL)")
	payload := flag.Int("payload", 4096, "payload size in bytes for a single run")
	sweep := flag.String("sweep", "", "comma-separated payload sizes for a sweep run, e.g. 4096,16384,65536")
	propagationWait := flag.Duration("propagation", 30*time.Second, "propagation wait between temp-stream writes and the Copy command")
	metricsAddr := flag.String("metrics", "0.0.0.0:9102", "prometheus listen address; empty disables")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		fmt.Fprintf(os.Stderr, "cp-bench: caught %s, shutting down\n", s)
		cancel()
	}()

	sizes := []int{*payload}
	if *sweep != "" {
		parts := strings.Split(*sweep, ",")
		sizes = sizes[:0]
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "cp-bench: invalid sweep size %q\n", p)
				os.Exit(2)
			}
			sizes = append(sizes, n)
		}
		if len(sizes) == 0 {
			fmt.Fprintln(os.Stderr, "cp-bench: -sweep is empty")
			os.Exit(2)
		}
	}

	for _, size := range sizes {
		cfg := cpbench.Config{
			ThinClientConfigPath: *configFile,
			LogLevel:             *logLevel,
			PayloadBytes:         size,
			PropagationWait:      *propagationWait,
			MetricsAddress:       *metricsAddr,
		}
		fmt.Printf("cp-bench: starting payload=%d bytes\n", size)
		r, err := cpbench.Run(ctx, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cp-bench: payload=%d FAILED: %v\n", size, err)
			continue
		}
		fmt.Printf("cp-bench: payload=%d chunks=%d duration=%s bytes_per_sec=%.1f\n",
			r.PayloadBytes, r.NumChunks, r.Duration.Round(time.Millisecond), r.BytesPerSec)
	}
}
