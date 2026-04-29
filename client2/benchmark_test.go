// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
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

// benchGatewayServer simulates a Gateway server accepting client handshakes
func benchGatewayServer(listener net.Listener, serverLinkPrivKey kem.PrivateKey, serverIdPubKey sign.PublicKey, done chan struct{}, wg *sync.WaitGroup, connWg *sync.WaitGroup) {
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
			defer c.Close()
			defer connWg.Done()

			cfg := &wire.SessionConfig{
				KEMScheme:         benchKEMScheme,
				Geometry:          benchGeometry,
				Authenticator:     &acceptAllAuthenticator{},
				AdditionalData:    identityHash[:],
				AuthenticationKey: serverLinkPrivKey,
				RandomReader:      rand.Reader,
			}
			session, err := wire.NewSession(cfg, false)
			if err != nil {
				return
			}
			defer session.Close()

			c.SetDeadline(time.Now().Add(30 * time.Second))
			session.Initialize(c)
		}(conn)
	}
}

// acceptAllAuthenticator accepts all peers (simulates Gateway accepting clients)
type acceptAllAuthenticator struct{}

func (a *acceptAllAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	return true
}

// handshakeStats holds statistics from a batch of concurrent handshakes
type handshakeStats struct {
	avgUs  float64
	minUs  float64
	maxUs  float64
	count  int
	errors int
}

// BenchmarkClientHandshakeConcurrency benchmarks multiple clients connecting
// to a Gateway server concurrently
func BenchmarkClientHandshakeConcurrency(b *testing.B) {
	concurrencyLevels := []int{1, 5, 10, 20, 50}

	// Setup Gateway server
	_, serverLinkPrivKey, err := benchKEMScheme.GenerateKeyPair()
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
	var connWg sync.WaitGroup // Tracks in-flight server-side handshakes
	serverWg.Add(1)
	go benchGatewayServer(listener, serverLinkPrivKey, serverIdPubKey, done, &serverWg, &connWg)
	defer func() {
		close(done)
		serverWg.Wait()
	}()

	serverAddr := listener.Addr().String()

	// Pre-generate client keys for all concurrency levels
	maxConcurrency := 50
	clientKeys := make([]kem.PrivateKey, maxConcurrency)
	queueIDs := make([][]byte, maxConcurrency)
	for i := 0; i < maxConcurrency; i++ {
		_, clientLinkPrivKey, _ := benchKEMScheme.GenerateKeyPair()
		clientKeys[i] = clientLinkPrivKey
		queueID := make([]byte, 16)
		rand.Reader.Read(queueID)
		queueIDs[i] = queueID
	}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("clients-%d", concurrency), func(b *testing.B) {
			// Accumulators for aggregating stats across iterations
			var totalAvg float64
			var globalMin, globalMax float64
			var totalCount, totalErrors int
			first := true

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				stats := runClientConcurrentHandshakes(serverAddr, clientKeys, queueIDs, concurrency)
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

				// Wait for all server-side handshakes to complete before next iteration
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

func runClientConcurrentHandshakes(addr string, clientKeys []kem.PrivateKey, queueIDs [][]byte, concurrency int) handshakeStats {
	var wg sync.WaitGroup
	var barrier sync.WaitGroup
	barrier.Add(1)

	durations := make([]time.Duration, concurrency)
	errors := make([]error, concurrency)

	// Pre-create sessions before the barrier to isolate handshake timing
	sessions := make([]*wire.Session, concurrency)
	for c := 0; c < concurrency; c++ {
		cfg := &wire.SessionConfig{
			KEMScheme:         benchKEMScheme,
			Geometry:          benchGeometry,
			Authenticator:     &acceptAllAuthenticator{},
			AdditionalData:    queueIDs[c%len(queueIDs)],
			AuthenticationKey: clientKeys[c%len(clientKeys)],
			RandomReader:      rand.Reader,
		}
		session, err := wire.NewSession(cfg, true)
		if err != nil {
			return handshakeStats{errors: concurrency}
		}
		sessions[c] = session
	}

	for c := 0; c < concurrency; c++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer sessions[idx].Close()

			barrier.Wait() // All goroutines wait here

			// === TIMED SECTION: dial + handshake only ===
			start := time.Now()

			conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
			if err != nil {
				errors[idx] = err
				durations[idx] = time.Since(start)
				return
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(30 * time.Second))
			if err = sessions[idx].Initialize(conn); err != nil {
				errors[idx] = err
				durations[idx] = time.Since(start)
				return
			}

			durations[idx] = time.Since(start)
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
