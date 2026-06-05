// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package cpbench drives end-to-end pigeonhole-cp benchmarks. One run
// produces a random payload of a given size, uses
// CreateCourierEnvelopesFromPayload to split it into copy-stream
// chunks, writes the chunks to a temporary stream, issues a Copy
// command via ARQ, and reads them back from the destination channel,
// reconstructing the payload to verify integrity. The wall-clock from
// the first chunk write to the last chunk read is the "total seconds"
// measurement; bytes/sec is the payload size divided by that
// duration.
//
// The CTIDH per-Sphinx-packet cost is amortised over the payload, so
// throughput in bytes/sec scales with the chunk size that
// CreateCourierEnvelopesFromPayload produces; that in turn scales with
// the Sphinx UserForwardPayloadLength. This package's metrics make
// that relationship observable from prometheus directly.
package cpbench

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
)

// Config configures one run of the cp benchmark.
type Config struct {
	// ThinClientConfigPath points at a thinclient.toml on disk.
	ThinClientConfigPath string

	// LogLevel is the per-client log verbosity. ERROR keeps the output
	// readable; DEBUG is useful for chasing intermittent failures.
	LogLevel string

	// PayloadBytes is the size of the random payload Alice writes.
	// The benchmark wraps it with a 4-byte length prefix so Bob can
	// stop reading at the right point.
	PayloadBytes int

	// PropagationWait is how long to sleep after writing all
	// temp-stream chunks before issuing the Copy command, to let the
	// chunks propagate to the storage replicas. 30 s is the value
	// used by the existing docker tests.
	PropagationWait time.Duration

	// MetricsAddress, if non-empty, exposes the cp-bench prometheus
	// surface here. Empty disables the listener.
	MetricsAddress string
}

// Result captures the throughput measurement from a single run.
type Result struct {
	PayloadBytes int
	NumChunks    int
	Duration     time.Duration
	BytesPerSec  float64
}

// Run executes a single cp benchmark cycle.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.ThinClientConfigPath == "" {
		return nil, errors.New("cpbench: ThinClientConfigPath is required")
	}
	if cfg.PayloadBytes <= 0 {
		return nil, errors.New("cpbench: PayloadBytes must be > 0")
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "ERROR"
	}
	if cfg.PropagationWait <= 0 {
		cfg.PropagationWait = 30 * time.Second
	}

	StartListener(cfg.MetricsAddress)
	label := strconv.Itoa(cfg.PayloadBytes)

	alice, err := dial(cfg)
	if err != nil {
		errorsByStage.With(map[string]string{"stage": "dial_alice"}).Inc()
		return nil, fmt.Errorf("cpbench: alice dial: %w", err)
	}
	defer alice.Close()

	bob, err := dial(cfg)
	if err != nil {
		errorsByStage.With(map[string]string{"stage": "dial_bob"}).Inc()
		return nil, fmt.Errorf("cpbench: bob dial: %w", err)
	}
	defer bob.Close()

	destSeed := make([]byte, 32)
	if _, err := rand.Reader.Read(destSeed); err != nil {
		errorsByStage.With(map[string]string{"stage": "rand_seed"}).Inc()
		return nil, fmt.Errorf("cpbench: dest seed: %w", err)
	}
	destWriteCap, bobReadCap, err := alice.NewKeypair(destSeed)
	if err != nil {
		errorsByStage.With(map[string]string{"stage": "alice_dest_keypair"}).Inc()
		return nil, fmt.Errorf("cpbench: dest keypair: %w", err)
	}

	tempSeed := make([]byte, 32)
	if _, err := rand.Reader.Read(tempSeed); err != nil {
		errorsByStage.With(map[string]string{"stage": "rand_seed"}).Inc()
		return nil, fmt.Errorf("cpbench: temp seed: %w", err)
	}
	tempWriteCap, _, err := alice.NewKeypair(tempSeed)
	if err != nil {
		errorsByStage.With(map[string]string{"stage": "alice_temp_keypair"}).Inc()
		return nil, fmt.Errorf("cpbench: temp keypair: %w", err)
	}

	randomData := make([]byte, cfg.PayloadBytes)
	if _, err := rand.Reader.Read(randomData); err != nil {
		errorsByStage.With(map[string]string{"stage": "rand_payload"}).Inc()
		return nil, fmt.Errorf("cpbench: random payload: %w", err)
	}
	payload := make([]byte, 4+len(randomData))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(randomData)))
	copy(payload[4:], randomData)

	chunks, _, err := alice.CreateCourierEnvelopesFromPayload(payload, destWriteCap, true, true)
	if err != nil {
		errorsByStage.With(map[string]string{"stage": "create_courier_envelopes"}).Inc()
		return nil, fmt.Errorf("cpbench: CreateCourierEnvelopesFromPayload: %w", err)
	}
	if len(chunks) == 0 {
		errorsByStage.With(map[string]string{"stage": "create_courier_envelopes"}).Inc()
		return nil, errors.New("cpbench: CreateCourierEnvelopesFromPayload returned no chunks")
	}
	chunksObserved.With(map[string]string{"payload_bytes": label}).Set(float64(len(chunks)))

	// Wall clock starts here: first measurable work is the write of
	// the first temp-stream chunk and ends with the last reconstructed
	// byte at Bob.
	start := time.Now()

	tempCap := tempWriteCap
	replyIndex := uint8(0)
	for i, chunk := range chunks {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		ciphertext, envDesc, envHash, nextTempCap, err := alice.EncryptWrite(chunk, tempCap)
		if err != nil {
			errorsByStage.With(map[string]string{"stage": "alice_encrypt_write_chunk"}).Inc()
			return nil, fmt.Errorf("cpbench: encrypt write chunk %d: %w", i+1, err)
		}
		if _, err := alice.StartResendingEncryptedMessage(nil, tempCap, &replyIndex, envDesc, ciphertext, envHash); err != nil {
			errorsByStage.With(map[string]string{"stage": "alice_send_chunk"}).Inc()
			return nil, fmt.Errorf("cpbench: send chunk %d: %w", i+1, err)
		}
		tempCap = nextTempCap
	}

	// Propagation wait: temp-stream writes hit replica primaries and
	// then replicate to peers; the Copy command will fail-fast if
	// replicas have not yet seen the chunks. 30 s matches the existing
	// docker test recipe.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(cfg.PropagationWait):
	}

	if err := alice.StartResendingCopyCommand(tempWriteCap); err != nil {
		errorsByStage.With(map[string]string{"stage": "alice_copy_command"}).Inc()
		return nil, fmt.Errorf("cpbench: Copy command: %w", err)
	}

	// Bob reconstructs the payload chunk by chunk until the length
	// prefix says he is done.
	bobCap := bobReadCap
	var reconstructed []byte
	var expectedLength uint32
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		bobCt, bobEnvDesc, bobEnvHash, bobNextCap, err := bob.EncryptRead(bobCap)
		if err != nil {
			errorsByStage.With(map[string]string{"stage": "bob_encrypt_read"}).Inc()
			return nil, fmt.Errorf("cpbench: bob encrypt read: %w", err)
		}
		result, err := bob.StartResendingEncryptedMessage(bobCap, nil, &replyIndex, bobEnvDesc, bobCt, bobEnvHash)
		if err != nil {
			errorsByStage.With(map[string]string{"stage": "bob_read"}).Inc()
			return nil, fmt.Errorf("cpbench: bob read: %w", err)
		}
		if len(result.Plaintext) == 0 {
			errorsByStage.With(map[string]string{"stage": "bob_empty_chunk"}).Inc()
			return nil, errors.New("cpbench: bob received empty chunk")
		}
		reconstructed = append(reconstructed, result.Plaintext...)
		if expectedLength == 0 && len(reconstructed) >= 4 {
			expectedLength = binary.BigEndian.Uint32(reconstructed[:4])
		}
		if expectedLength > 0 && uint32(len(reconstructed)) >= expectedLength+4 {
			break
		}
		bobCap = bobNextCap
	}

	elapsed := time.Since(start)
	totalSeconds.With(map[string]string{"payload_bytes": label}).Observe(elapsed.Seconds())

	if uint32(len(reconstructed)) < expectedLength+4 {
		runsTotal.With(map[string]string{"result": "error"}).Inc()
		errorsByStage.With(map[string]string{"stage": "short_payload"}).Inc()
		return nil, fmt.Errorf("cpbench: reconstructed %d bytes, expected %d", len(reconstructed), expectedLength+4)
	}
	runsTotal.With(map[string]string{"result": "ok"}).Inc()

	bps := float64(cfg.PayloadBytes) / elapsed.Seconds()
	bytesPerSec.With(map[string]string{"payload_bytes": label}).Set(bps)

	return &Result{
		PayloadBytes: cfg.PayloadBytes,
		NumChunks:    len(chunks),
		Duration:     elapsed,
		BytesPerSec:  bps,
	}, nil
}

func dial(cfg Config) (*thin.ThinClient, error) {
	tcCfg, err := thin.LoadFile(cfg.ThinClientConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load thinclient config: %w", err)
	}
	c := thin.NewThinClient(tcCfg, &config.Logging{Disable: false, Level: cfg.LogLevel})
	if err := c.Dial(); err != nil {
		return nil, err
	}
	return c, nil
}
