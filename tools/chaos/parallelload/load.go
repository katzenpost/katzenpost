// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package parallelload drives N concurrent thin clients in pigeonhole
// write-then-read iterations. It is a stress generator and a measurement
// harness, not a correctness test: each iteration's per-client latency
// and outcome is recorded to prometheus so that throughput-vs-load
// curves, Jain fairness across client_ids, and response-time CDFs can
// be plotted from Grafana.
//
// The tool is structured to allow either a single-step run (fixed
// concurrency for a fixed duration) or a sweep run (concurrency
// increasing in stages, e.g. 1, 2, 4, 8, 16). The sweep emits a
// `katzenpost_parallel_load_sweep_step_clients` gauge so Grafana panels
// can align step boundaries with the throughput and latency curves.
package parallelload

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
)

// Config configures one run of the parallel-load tool. Either Duration
// (single-step mode) or SweepSteps (multi-step mode) must be set.
type Config struct {
	// ThinClientConfigPath points at a thinclient.toml on disk.
	ThinClientConfigPath string

	// LogLevel is the per-client log verbosity. Anything but ERROR is
	// usually too noisy at high concurrency.
	LogLevel string

	// Clients is the offered concurrency for single-step mode.
	Clients int

	// Duration is how long single-step mode runs.
	Duration time.Duration

	// SweepSteps overrides Clients when non-empty. Each integer is one
	// concurrency level; SweepStepDuration applies to each.
	SweepSteps []int

	// SweepStepDuration is how long each step in SweepSteps holds.
	SweepStepDuration time.Duration

	// PayloadBytes is the per-iteration message size.
	PayloadBytes int

	// MetricsAddress, if non-empty, exposes the prometheus surface here.
	MetricsAddress string
}

// Run executes the load run described by cfg. It blocks until the run
// finishes or ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	if cfg.ThinClientConfigPath == "" {
		return errors.New("parallelload: ThinClientConfigPath is required")
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "ERROR"
	}
	if cfg.PayloadBytes <= 0 {
		cfg.PayloadBytes = 256
	}

	StartListener(cfg.MetricsAddress)

	if len(cfg.SweepSteps) == 0 {
		if cfg.Clients <= 0 {
			return errors.New("parallelload: Clients must be > 0")
		}
		if cfg.Duration <= 0 {
			return errors.New("parallelload: Duration must be > 0")
		}
		return runStep(ctx, cfg, cfg.Clients, cfg.Duration)
	}

	if cfg.SweepStepDuration <= 0 {
		return errors.New("parallelload: SweepStepDuration must be > 0 when SweepSteps is set")
	}
	for _, n := range cfg.SweepSteps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		SetSweepStep(n)
		fmt.Printf("parallel-load: sweep step starting, clients=%d duration=%s\n", n, cfg.SweepStepDuration)
		if err := runStep(ctx, cfg, n, cfg.SweepStepDuration); err != nil {
			return err
		}
	}
	SetSweepStep(0)
	return nil
}

func runStep(ctx context.Context, cfg Config, clients int, dur time.Duration) error {
	stepCtx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()

	SetActiveClients(clients)
	defer SetActiveClients(0)

	var wg sync.WaitGroup
	var totalIters int64
	for i := 0; i < clients; i++ {
		wg.Add(1)
		clientID := fmt.Sprintf("c%03d", i)
		go func() {
			defer wg.Done()
			n := driveClient(stepCtx, cfg, clientID)
			atomic.AddInt64(&totalIters, int64(n))
		}()
	}
	wg.Wait()
	fmt.Printf("parallel-load: step done, clients=%d iterations=%d elapsed=%s\n", clients, totalIters, dur)
	return nil
}

// driveClient connects one thin client to the daemon and runs pigeonhole
// write/read cycles until ctx is cancelled. Returns the number of
// successful iterations.
func driveClient(ctx context.Context, cfg Config, clientID string) int {
	tcCfg, err := thin.LoadFile(cfg.ThinClientConfigPath)
	if err != nil {
		IterationFailed(clientID, "setup", "load_config")
		return 0
	}
	logging := &config.Logging{Disable: false, Level: cfg.LogLevel}
	client := thin.NewThinClient(tcCfg, logging)
	if err := client.Dial(); err != nil {
		IterationFailed(clientID, "setup", "dial")
		return 0
	}
	defer client.Close()

	successes := 0
	payload := make([]byte, cfg.PayloadBytes)

	for {
		select {
		case <-ctx.Done():
			return successes
		default:
		}

		// New keypair per iteration so each cycle is self-contained.
		// Avoids the need to track per-client BACAP index state across
		// the run; the cost is one extra keypair-generation per cycle.
		seed := make([]byte, 32)
		if _, err := rand.Reader.Read(seed); err != nil {
			IterationFailed(clientID, "keypair", "rand_read")
			continue
		}
		writeCap, readCap, firstIndex, err := client.NewKeypair(seed)
		if err != nil {
			IterationFailed(clientID, "keypair", "new_keypair")
			continue
		}

		// Fresh payload bytes each cycle so the daemon cannot trivially
		// dedupe in any layer.
		if _, err := rand.Reader.Read(payload); err != nil {
			IterationFailed(clientID, "keypair", "rand_payload")
			continue
		}

		iterStart := time.Now()

		writeStart := time.Now()
		ciphertext, envDesc, envHash, _, err := client.EncryptWrite(payload, writeCap, firstIndex)
		if err != nil {
			IterationFailed(clientID, "encrypt_write", classify(err))
			continue
		}
		replyIndex := uint8(0)
		_, err = client.StartResendingEncryptedMessage(nil, writeCap, nil, &replyIndex, envDesc, ciphertext, envHash)
		if err != nil {
			IterationFailed(clientID, "send_write", classify(err))
			continue
		}
		OperationLatency("write", time.Since(writeStart))

		readStart := time.Now()
		readCt, readEnvDesc, readEnvHash, _, err := client.EncryptRead(readCap, firstIndex)
		if err != nil {
			IterationFailed(clientID, "encrypt_read", classify(err))
			continue
		}
		firstIndexBytes, err := firstIndex.MarshalBinary()
		if err != nil {
			IterationFailed(clientID, "encrypt_read", "marshal_index")
			continue
		}
		result, err := client.StartResendingEncryptedMessage(readCap, nil, firstIndexBytes, &replyIndex, readEnvDesc, readCt, readEnvHash)
		if err != nil {
			IterationFailed(clientID, "send_read", classify(err))
			continue
		}
		OperationLatency("read", time.Since(readStart))

		// Loose verification: the daemon decrypted the payload back.
		// Stronger byte-equality verification is a correctness test; here we
		// only check the daemon delivered a non-empty plaintext, since the
		// ARQ matched against an envelope hash a few lines above.
		if len(result.Plaintext) == 0 {
			IterationFailed(clientID, "verify", "empty_plaintext")
			continue
		}

		IterationCompleted(clientID, time.Since(iterStart))
		successes++
	}
}

// classify reduces an error to a short kind label for the errors
// counter. It is best-effort: untyped errors get kind=other.
func classify(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, thin.ErrTombstone) {
		return "tombstone"
	}
	if errors.Is(err, thin.ErrBoxIDNotFound) {
		return "box_not_found"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return "other"
}
