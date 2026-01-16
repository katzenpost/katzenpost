// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
)

var (
	benchKEMScheme  = schemes.ByName("xwing")
	benchSignScheme = signSchemes.ByName("Ed25519")
	benchGeometry   = geo.GeometryFromUserForwardPayloadLength(
		ecdh.Scheme(rand.Reader),
		2000,
		true,
		5,
	)
)

// benchServer runs a mock server that accepts connections and performs handshakes
// connWg tracks in-flight connection handshakes to prevent iteration overlap
func benchServer(listener net.Listener, serverLinkPrivKey kem.PrivateKey, serverIdPubKey sign.PublicKey, done chan struct{}, wg *sync.WaitGroup, connWg *sync.WaitGroup) {
	defer wg.Done()

	// Pre-compute identity hash once
	identityHash := hash.Sum256From(serverIdPubKey)

	for {
		select {
		case <-done:
			return
		default:
		}

		listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
		conn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		connWg.Add(1)
		go func(c net.Conn) {
			defer connWg.Done()
			defer c.Close()

			cfg := &wire.SessionConfig{
				KEMScheme:         benchKEMScheme,
				Geometry:          benchGeometry,
				Authenticator:     &acceptAllAuthenticator{},
				AdditionalData:    identityHash[:],
				AuthenticationKey: serverLinkPrivKey,
				RandomReader:      rand.Reader,
			}
			session, err := wire.NewPKISession(cfg, false)
			if err != nil {
				return
			}
			defer session.Close()

			c.SetDeadline(time.Now().Add(30 * time.Second))
			session.Initialize(c)
		}(conn)
	}
}

// handshakeStats holds statistics from a batch of concurrent handshakes
type handshakeStats struct {
	avgUs  float64
	minUs  float64
	maxUs  float64
	count  int
	errors int
}

// acceptAllAuthenticator accepts any peer for benchmarking
type acceptAllAuthenticator struct{}

func (a *acceptAllAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	return true
}

// BenchmarkHandshakeConcurrency benchmarks handshake performance under different concurrency levels
func BenchmarkHandshakeConcurrency(b *testing.B) {
	concurrencyLevels := []int{1, 2, 5, 10, 20}

	// Setup server
	serverLinkPubKey, serverLinkPrivKey, err := benchKEMScheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate server link keypair: %v", err)
	}
	serverIdPubKey, _, err := benchSignScheme.GenerateKey()
	if err != nil {
		b.Fatalf("failed to generate server identity keypair: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	var serverWg sync.WaitGroup
	var connWg sync.WaitGroup
	serverWg.Add(1)
	go benchServer(listener, serverLinkPrivKey, serverIdPubKey, done, &serverWg, &connWg)
	defer func() {
		close(done)
		serverWg.Wait()
	}()

	// Send logs to /dev/null to avoid stdout I/O overhead
	// while still exercising the full DEBUG logging code paths
	logBackend, err := log.New("/dev/null", "DEBUG", false)
	if err != nil {
		b.Fatalf("failed to create log backend: %v", err)
	}

	// Create peer configuration
	peer := &config.Authority{
		Identifier:         "bench-server",
		IdentityPublicKey:  serverIdPubKey,
		LinkPublicKey:      serverLinkPubKey,
		PKISignatureScheme: benchSignScheme.Name(),
		WireKEMScheme:      benchKEMScheme.Name(),
		Addresses:          []string{fmt.Sprintf("tcp://%s", listener.Addr().String())},
	}

	// Pre-generate client keys for all concurrency levels
	maxConcurrency := 20
	clientKeys := make([]kem.PrivateKey, maxConcurrency)
	for i := 0; i < maxConcurrency; i++ {
		_, clientLinkPrivKey, _ := benchKEMScheme.GenerateKeyPair()
		clientKeys[i] = clientLinkPrivKey
	}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("concurrent-%d", concurrency), func(b *testing.B) {
			// Accumulators for aggregating stats across iterations
			var totalAvg float64
			var globalMin, globalMax float64
			var totalCount, totalErrors int
			first := true

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				stats := runConcurrentHandshakes(logBackend, peer, clientKeys, concurrency)
				totalAvg += stats.avgUs
				totalCount += stats.count
				totalErrors += stats.errors

				// Track global min/max across all iterations
				if first || stats.minUs < globalMin {
					globalMin = stats.minUs
				}
				if first || stats.maxUs > globalMax {
					globalMax = stats.maxUs
				}
				first = false

				// Wait for server-side handshakes to complete before next iteration
				connWg.Wait()
			}

			// Report aggregated metrics
			if b.N > 0 && totalCount > 0 {
				b.ReportMetric(totalAvg/float64(b.N), "avg_us")
				b.ReportMetric(globalMin, "min_us")
				b.ReportMetric(globalMax, "max_us")
			}
		})
	}
}

func runConcurrentHandshakes(logBackend *log.Backend, peer *config.Authority, clientKeys []kem.PrivateKey, concurrency int) handshakeStats {
	var wg sync.WaitGroup
	var barrier sync.WaitGroup
	barrier.Add(1)

	durations := make([]time.Duration, concurrency)
	errors := make([]error, concurrency)

	// Pre-create connectors before the barrier to isolate handshake timing
	connectors := make([]*connector, concurrency)
	for c := 0; c < concurrency; c++ {
		clientLinkPrivKey := clientKeys[c%len(clientKeys)]
		cfg := &Config{
			KEMScheme:           benchKEMScheme,
			PKISignatureScheme:  benchSignScheme,
			LinkKey:             clientLinkPrivKey,
			LogBackend:          logBackend,
			Authorities:         []*config.Authority{peer},
			Geo:                 benchGeometry,
			DialTimeoutSec:      10,
			HandshakeTimeoutSec: 30,
			ResponseTimeoutSec:  30,
		}
		connectors[c] = newConnector(cfg)
	}

	for c := 0; c < concurrency; c++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			clientLinkPrivKey := clientKeys[idx%len(clientKeys)]

			barrier.Wait() // All goroutines wait here

			// === TIMED SECTION: dial + handshake only ===
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			c, err := connectors[idx].initSession(ctx, clientLinkPrivKey, nil, peer)
			durations[idx] = time.Since(start)
			if err != nil {
				errors[idx] = err
				return
			}
			c.conn.Close()
		}(c)
	}

	barrier.Done() // Release all at once!
	wg.Wait()

	// Compute statistics
	var total time.Duration
	var minDur, maxDur time.Duration
	successCount := 0
	errorCount := 0

	for i, d := range durations {
		if errors[i] != nil {
			errorCount++
			continue
		}
		successCount++
		total += d
		if minDur == 0 || d < minDur {
			minDur = d
		}
		if d > maxDur {
			maxDur = d
		}
	}

	if successCount > 0 {
		avg := total / time.Duration(successCount)
		return handshakeStats{
			avgUs:  float64(avg.Microseconds()),
			minUs:  float64(minDur.Microseconds()),
			maxUs:  float64(maxDur.Microseconds()),
			count:  successCount,
			errors: errorCount,
		}
	}
	return handshakeStats{errors: errorCount}
}

// BenchmarkHandshakeLatencyDistribution measures handshake latency distribution
func BenchmarkHandshakeLatencyDistribution(b *testing.B) {
	// Setup server
	serverLinkPubKey, serverLinkPrivKey, err := benchKEMScheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate server link keypair: %v", err)
	}
	serverIdPubKey, _, err := benchSignScheme.GenerateKey()
	if err != nil {
		b.Fatalf("failed to generate server identity keypair: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	var serverWg sync.WaitGroup
	var connWg sync.WaitGroup
	serverWg.Add(1)
	go benchServer(listener, serverLinkPrivKey, serverIdPubKey, done, &serverWg, &connWg)
	defer func() {
		close(done)
		serverWg.Wait()
	}()

	// Send logs to /dev/null to avoid stdout I/O overhead
	// while still exercising the full DEBUG logging code paths
	logBackend, err := log.New("/dev/null", "DEBUG", false)
	if err != nil {
		b.Fatalf("failed to create log backend: %v", err)
	}

	_, clientLinkPrivKey, err := benchKEMScheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate client link keypair: %v", err)
	}

	peer := &config.Authority{
		Identifier:         "bench-server",
		IdentityPublicKey:  serverIdPubKey,
		LinkPublicKey:      serverLinkPubKey,
		PKISignatureScheme: benchSignScheme.Name(),
		WireKEMScheme:      benchKEMScheme.Name(),
		Addresses:          []string{fmt.Sprintf("tcp://%s", listener.Addr().String())},
	}

	cfg := &Config{
		KEMScheme:           benchKEMScheme,
		PKISignatureScheme:  benchSignScheme,
		LinkKey:             clientLinkPrivKey,
		LogBackend:          logBackend,
		Authorities:         []*config.Authority{peer},
		Geo:                 benchGeometry,
		DialTimeoutSec:      10,
		HandshakeTimeoutSec: 30,
		ResponseTimeoutSec:  30,
	}

	conn := newConnector(cfg)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		c, err := conn.initSession(ctx, clientLinkPrivKey, nil, peer)
		cancel()
		if err != nil {
			b.Fatalf("handshake failed: %v", err)
		}
		c.conn.Close()
		connWg.Wait() // Wait for server-side handshake to complete
	}
}
