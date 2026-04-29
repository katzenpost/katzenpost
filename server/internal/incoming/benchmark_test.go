// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package incoming

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

// benchMixServer simulates a mix server accepting and performing handshakes
// connWg tracks in-flight connection handshakes to prevent iteration overlap
func benchMixServer(listener net.Listener, serverLinkPrivKey kem.PrivateKey, serverIdPubKey sign.PublicKey, authorizedPeers map[[hash.HashSize]byte]bool, done chan struct{}, wg *sync.WaitGroup, connWg *sync.WaitGroup) {
	defer wg.Done()

	// Pre-compute identity hash once
	identityHash := hash.Sum256From(serverIdPubKey)
	auth := &benchMixAuthenticator{authorizedPeers: authorizedPeers}

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

// benchMixAuthenticator simulates IsPeerValid with map lookups like real mix server
type benchMixAuthenticator struct {
	authorizedPeers map[[hash.HashSize]byte]bool
}

func (a *benchMixAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	// Simulate client connection (no additional data) - like Gateway clients
	if len(creds.AdditionalData) == 0 {
		return true
	}

	// Simulate mix/node authentication with map lookup
	if len(creds.AdditionalData) == hash.HashSize {
		pk := [hash.HashSize]byte{}
		copy(pk[:], creds.AdditionalData[:hash.HashSize])
		_, authorized := a.authorizedPeers[pk]
		return authorized
	}

	return false
}

// acceptAllAuthenticator accepts all peers (for client-side benchmarks)
type acceptAllAuthenticator struct{}

func (a *acceptAllAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	return true
}

// BenchmarkMixServerHandshakeConcurrency benchmarks mix server handshake under concurrent load
func BenchmarkMixServerHandshakeConcurrency(b *testing.B) {
	concurrencyLevels := []int{1, 2, 5, 10, 20}

	// Setup server keys
	_, serverLinkPrivKey, err := benchKEMScheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate server link keypair: %v", err)
	}
	serverIdPubKey, _, err := benchSignScheme.GenerateKey()
	if err != nil {
		b.Fatalf("failed to generate server identity keypair: %v", err)
	}

	// Create authorized peers map (simulating mix-to-mix authentication)
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
	go benchMixServer(listener, serverLinkPrivKey, serverIdPubKey, authorizedPeers, done, &serverWg, &connWg)
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
				stats := runMixConcurrentHandshakes(serverAddr, clientKeys, clientIdKeys, concurrency)
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

func runMixConcurrentHandshakes(serverAddr string, clientKeys []kem.PrivateKey, clientIdKeys []sign.PublicKey, concurrency int) handshakeStats {
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

// BenchmarkMixServerClientHandshake benchmarks client connections to mix server (Gateway scenario)
func BenchmarkMixServerClientHandshake(b *testing.B) {
	concurrencyLevels := []int{1, 5, 10, 20, 50}

	// Setup server keys
	_, serverLinkPrivKey, err := benchKEMScheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate server link keypair: %v", err)
	}
	serverIdPubKey, _, err := benchSignScheme.GenerateKey()
	if err != nil {
		b.Fatalf("failed to generate server identity keypair: %v", err)
	}

	// Empty authorized peers - clients don't need to be in the map
	authorizedPeers := make(map[[hash.HashSize]byte]bool)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	var serverWg sync.WaitGroup
	var connWg sync.WaitGroup
	serverWg.Add(1)
	go benchMixServer(listener, serverLinkPrivKey, serverIdPubKey, authorizedPeers, done, &serverWg, &connWg)
	defer func() {
		close(done)
		serverWg.Wait()
	}()

	serverAddr := listener.Addr().String()

	// Pre-generate client keys for all concurrency levels
	maxConcurrency := 50
	clientKeys := make([]kem.PrivateKey, maxConcurrency)
	for i := 0; i < maxConcurrency; i++ {
		_, clientLinkPrivKey, _ := benchKEMScheme.GenerateKeyPair()
		clientKeys[i] = clientLinkPrivKey
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
				stats := runClientConcurrentHandshakes(serverAddr, clientKeys, concurrency)
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

func runClientConcurrentHandshakes(serverAddr string, clientKeys []kem.PrivateKey, concurrency int) handshakeStats {
	var wg sync.WaitGroup
	var barrier sync.WaitGroup
	barrier.Add(1)

	durations := make([]time.Duration, concurrency)
	errors := make([]error, concurrency)

	// Pre-create sessions before the barrier to isolate handshake timing
	sessions := make([]*wire.Session, concurrency)
	for c := 0; c < concurrency; c++ {
		clientLinkPrivKey := clientKeys[c%len(clientKeys)]
		cfg := &wire.SessionConfig{
			KEMScheme:         benchKEMScheme,
			Geometry:          benchGeometry,
			Authenticator:     &acceptAllAuthenticator{},
			AdditionalData:    nil, // Clients don't send identity
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
