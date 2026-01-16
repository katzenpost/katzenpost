// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package outgoing

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

// benchTargetMixServer simulates a target mix server accepting handshakes
// connWg tracks in-flight connection handshakes to prevent iteration overlap
func benchTargetMixServer(listener net.Listener, serverLinkPrivKey kem.PrivateKey, serverIdPubKey sign.PublicKey, authorizedPeers map[[hash.HashSize]byte]bool, done chan struct{}, wg *sync.WaitGroup, connWg *sync.WaitGroup) {
	defer wg.Done()

	// Pre-compute identity hash once
	identityHash := hash.Sum256From(serverIdPubKey)
	auth := &benchOutgoingAuthenticator{authorizedPeers: authorizedPeers}

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
				Authenticator:     auth,
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

// handshakeStats holds statistics from a batch of concurrent handshakes
type handshakeStats struct {
	avgUs  float64
	minUs  float64
	maxUs  float64
	count  int
	errors int
}

// benchOutgoingAuthenticator simulates IsPeerValid for mix-to-mix connections
type benchOutgoingAuthenticator struct {
	authorizedPeers map[[hash.HashSize]byte]bool
}

func (a *benchOutgoingAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	if len(creds.AdditionalData) == hash.HashSize {
		pk := [hash.HashSize]byte{}
		copy(pk[:], creds.AdditionalData[:hash.HashSize])
		_, authorized := a.authorizedPeers[pk]
		return authorized
	}
	return false
}

// acceptAllAuthenticator accepts all peers
type acceptAllAuthenticator struct{}

func (a *acceptAllAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	return true
}

// BenchmarkOutgoingConnHandshake benchmarks outgoing connection handshakes (mix-to-mix)
func BenchmarkOutgoingConnHandshake(b *testing.B) {
	concurrencyLevels := []int{1, 2, 5, 10, 20}

	// Setup target server keys
	_, serverLinkPrivKey, err := benchKEMScheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate server link keypair: %v", err)
	}
	serverIdPubKey, _, err := benchSignScheme.GenerateKey()
	if err != nil {
		b.Fatalf("failed to generate server identity keypair: %v", err)
	}

	// Create authorized peers map and client keys
	authorizedPeers := make(map[[hash.HashSize]byte]bool)
	clientKeys := make([]kem.PrivateKey, 50)
	clientIdKeys := make([]sign.PublicKey, 50)
	for i := 0; i < 50; i++ {
		_, clientLinkPrivKey, _ := benchKEMScheme.GenerateKeyPair()
		clientIdPubKey, _, _ := benchSignScheme.GenerateKey()
		clientKeys[i] = clientLinkPrivKey
		clientIdKeys[i] = clientIdPubKey
		idHash := hash.Sum256From(clientIdPubKey)
		authorizedPeers[idHash] = true
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
	go benchTargetMixServer(listener, serverLinkPrivKey, serverIdPubKey, authorizedPeers, done, &serverWg, &connWg)
	defer func() {
		close(done)
		serverWg.Wait()
	}()

	serverAddr := listener.Addr().String()

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("concurrent-%d", concurrency), func(b *testing.B) {
			// Accumulators for aggregating stats across iterations
			var totalAvg float64
			var globalMin, globalMax float64
			var totalCount, totalErrors int
			first := true

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				stats := runOutgoingConcurrentHandshakes(serverAddr, clientKeys, clientIdKeys, concurrency)
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

func runOutgoingConcurrentHandshakes(serverAddr string, clientKeys []kem.PrivateKey, clientIdKeys []sign.PublicKey, concurrency int) handshakeStats {
	var wg sync.WaitGroup
	var barrier sync.WaitGroup
	barrier.Add(1)

	durations := make([]time.Duration, concurrency)
	errors := make([]error, concurrency)

	// Pre-create sessions before the barrier to isolate handshake timing
	sessions := make([]*wire.Session, concurrency)
	for c := 0; c < concurrency; c++ {
		clientLinkPrivKey := clientKeys[c%len(clientKeys)]
		clientIdPubKey := clientIdKeys[c%len(clientIdKeys)]
		identityHash := hash.Sum256From(clientIdPubKey)
		cfg := &wire.SessionConfig{
			KEMScheme:         benchKEMScheme,
			Geometry:          benchGeometry,
			Authenticator:     &acceptAllAuthenticator{},
			AdditionalData:    identityHash[:],
			AuthenticationKey: clientLinkPrivKey,
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
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			var d net.Dialer
			conn, err := d.DialContext(ctx, "tcp", serverAddr)
			if err != nil {
				errors[idx] = err
				return
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(30 * time.Second))
			err = sessions[idx].Initialize(conn)
			durations[idx] = time.Since(start)
			if err != nil {
				errors[idx] = err
				return
			}
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

// targetServer represents a target mix server for benchmarking
type targetServer struct {
	listener net.Listener
	done     chan struct{}
	wg       sync.WaitGroup
	connWg   sync.WaitGroup
}

// BenchmarkOutgoingMultipleTargets benchmarks connecting to multiple target mixes concurrently
func BenchmarkOutgoingMultipleTargets(b *testing.B) {
	numTargets := 5
	connectionsPerTarget := []int{1, 2, 5}

	// Setup multiple target servers (simulating mix layer)
	targets := make([]*targetServer, numTargets)

	// Client identity
	_, clientLinkPrivKey, err := benchKEMScheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate client link keypair: %v", err)
	}
	clientIdPubKey, _, err := benchSignScheme.GenerateKey()
	if err != nil {
		b.Fatalf("failed to generate client identity keypair: %v", err)
	}

	// Authorize this client on all targets
	clientIdHash := hash.Sum256From(clientIdPubKey)
	authorizedPeers := map[[hash.HashSize]byte]bool{clientIdHash: true}

	for i := 0; i < numTargets; i++ {
		_, serverLinkPrivKey, _ := benchKEMScheme.GenerateKeyPair()
		serverIdPubKey, _, _ := benchSignScheme.GenerateKey()

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatalf("failed to start listener %d: %v", i, err)
		}

		t := &targetServer{
			listener: listener,
			done:     make(chan struct{}),
		}
		t.wg.Add(1)
		go benchTargetMixServer(listener, serverLinkPrivKey, serverIdPubKey, authorizedPeers, t.done, &t.wg, &t.connWg)
		targets[i] = t
	}
	defer func() {
		for _, t := range targets {
			close(t.done)
			t.listener.Close()
			t.wg.Wait()
		}
	}()

	for _, connsPerTarget := range connectionsPerTarget {
		b.Run(fmt.Sprintf("targets-%d-conns-%d", numTargets, connsPerTarget), func(b *testing.B) {
			// Accumulators for aggregating stats across iterations
			var totalAvg float64
			var globalMin, globalMax float64
			var totalCount, totalErrors int
			first := true

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				stats := runMultiTargetHandshakes(targets, clientLinkPrivKey, clientIdPubKey, connsPerTarget)
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
				for _, t := range targets {
					t.connWg.Wait()
				}
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

func runMultiTargetHandshakes(targets []*targetServer, clientLinkPrivKey kem.PrivateKey, clientIdPubKey sign.PublicKey, connsPerTarget int) handshakeStats {
	var wg sync.WaitGroup
	var barrier sync.WaitGroup
	barrier.Add(1)

	totalConns := len(targets) * connsPerTarget
	durations := make([]time.Duration, totalConns)
	errors := make([]error, totalConns)

	// Pre-create sessions before the barrier to isolate handshake timing
	identityHash := hash.Sum256From(clientIdPubKey)
	sessions := make([]*wire.Session, totalConns)
	addrs := make([]string, totalConns)
	idx := 0
	for _, t := range targets {
		serverAddr := t.listener.Addr().String()
		for c := 0; c < connsPerTarget; c++ {
			cfg := &wire.SessionConfig{
				KEMScheme:         benchKEMScheme,
				Geometry:          benchGeometry,
				Authenticator:     &acceptAllAuthenticator{},
				AdditionalData:    identityHash[:],
				AuthenticationKey: clientLinkPrivKey,
				RandomReader:      rand.Reader,
			}
			session, err := wire.NewSession(cfg, true)
			if err != nil {
				return handshakeStats{errors: totalConns}
			}
			sessions[idx] = session
			addrs[idx] = serverAddr
			idx++
		}
	}

	for i := 0; i < totalConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer sessions[idx].Close()

			barrier.Wait()

			// === TIMED SECTION: dial + handshake only ===
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			var d net.Dialer
			conn, err := d.DialContext(ctx, "tcp", addrs[idx])
			if err != nil {
				errors[idx] = err
				return
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(30 * time.Second))
			err = sessions[idx].Initialize(conn)
			durations[idx] = time.Since(start)
			if err != nil {
				errors[idx] = err
				return
			}
		}(i)
	}

	barrier.Done()
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
