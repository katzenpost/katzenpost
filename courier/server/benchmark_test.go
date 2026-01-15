// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

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

// benchReplicaServer simulates a replica server accepting courier connections
func benchReplicaServer(listener net.Listener, serverLinkPrivKey kem.PrivateKey, serverIdPubKey sign.PublicKey, done chan struct{}, wg *sync.WaitGroup, connWg *sync.WaitGroup) {
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

// acceptAllAuthenticator accepts all peers
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

// BenchmarkCourierToReplicaHandshake benchmarks courier connecting to replica servers
func BenchmarkCourierToReplicaHandshake(b *testing.B) {
	concurrencyLevels := []int{1, 2, 5, 10}

	// Setup replica server
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
	go benchReplicaServer(listener, serverLinkPrivKey, serverIdPubKey, done, &serverWg, &connWg)
	defer func() {
		close(done)
		serverWg.Wait()
	}()

	serverAddr := listener.Addr().String()

	// Pre-generate courier keys for all concurrency levels
	maxConcurrency := 10
	courierKeys := make([]kem.PrivateKey, maxConcurrency)
	courierIdKeys := make([]sign.PublicKey, maxConcurrency)
	for i := 0; i < maxConcurrency; i++ {
		_, courierLinkPrivKey, _ := benchKEMScheme.GenerateKeyPair()
		courierIdPubKey, _, _ := benchSignScheme.GenerateKey()
		courierKeys[i] = courierLinkPrivKey
		courierIdKeys[i] = courierIdPubKey
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
				stats := runCourierConcurrentHandshakes(serverAddr, courierKeys, courierIdKeys, concurrency)
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

func runCourierConcurrentHandshakes(addr string, courierKeys []kem.PrivateKey, courierIdKeys []sign.PublicKey, concurrency int) handshakeStats {
	var wg sync.WaitGroup
	var barrier sync.WaitGroup
	barrier.Add(1)

	durations := make([]time.Duration, concurrency)
	errors := make([]error, concurrency)

	// Pre-create sessions before the barrier to isolate handshake timing
	sessions := make([]*wire.Session, concurrency)
	for c := 0; c < concurrency; c++ {
		courierLinkPrivKey := courierKeys[c%len(courierKeys)]
		courierIdPubKey := courierIdKeys[c%len(courierIdKeys)]
		identityHash := hash.Sum256From(courierIdPubKey)
		cfg := &wire.SessionConfig{
			KEMScheme:         benchKEMScheme,
			Geometry:          benchGeometry,
			Authenticator:     &acceptAllAuthenticator{},
			AdditionalData:    identityHash[:],
			AuthenticationKey: courierLinkPrivKey,
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

// BenchmarkMultipleReplicaHandshake benchmarks courier connecting to multiple replicas
func BenchmarkMultipleReplicaHandshake(b *testing.B) {
	numReplicas := 3

	// Setup multiple replica servers
	servers := make([]*replicaServer, numReplicas)

	for i := 0; i < numReplicas; i++ {
		_, linkPrivKey, _ := benchKEMScheme.GenerateKeyPair()
		idPubKey, _, _ := benchSignScheme.GenerateKey()

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatalf("failed to start listener %d: %v", i, err)
		}

		s := &replicaServer{
			listener:    listener,
			linkPrivKey: linkPrivKey,
			idPubKey:    idPubKey,
			done:        make(chan struct{}),
		}
		s.wg.Add(1)
		go benchReplicaServer(listener, linkPrivKey, idPubKey, s.done, &s.wg, &s.connWg)
		servers[i] = s
	}
	defer func() {
		for _, s := range servers {
			close(s.done)
			s.listener.Close()
			s.wg.Wait()
		}
	}()

	// Pre-generate courier keys
	_, courierLinkPrivKey, _ := benchKEMScheme.GenerateKeyPair()
	courierIdPubKey, _, _ := benchSignScheme.GenerateKey()

	b.Run(fmt.Sprintf("replicas-%d-parallel", numReplicas), func(b *testing.B) {
		// Accumulators for aggregating stats across iterations
		var totalUs float64

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			us := runParallelReplicaConnections(servers, courierLinkPrivKey, courierIdPubKey)
			totalUs += us

			// Wait for all server-side handshakes to complete before next iteration
			for _, s := range servers {
				s.connWg.Wait()
			}
		}

		// Report aggregated metrics (averaged over b.N iterations)
		if b.N > 0 {
			b.ReportMetric(totalUs/float64(b.N), "total_us")
		}
	})
}

type replicaServer struct {
	listener    net.Listener
	linkPrivKey kem.PrivateKey
	idPubKey    sign.PublicKey
	done        chan struct{}
	wg          sync.WaitGroup
	connWg      sync.WaitGroup // Tracks in-flight handshakes
}

func runParallelReplicaConnections(servers []*replicaServer, courierLinkPrivKey kem.PrivateKey, courierIdPubKey sign.PublicKey) float64 {
	identityHash := hash.Sum256From(courierIdPubKey)

	// Pre-create sessions before timing
	numServers := len(servers)
	sessions := make([]*wire.Session, numServers)
	addrs := make([]string, numServers)
	for i, s := range servers {
		cfg := &wire.SessionConfig{
			KEMScheme:         benchKEMScheme,
			Geometry:          benchGeometry,
			Authenticator:     &acceptAllAuthenticator{},
			AdditionalData:    identityHash[:],
			AuthenticationKey: courierLinkPrivKey,
			RandomReader:      rand.Reader,
		}
		session, _ := wire.NewSession(cfg, true)
		sessions[i] = session
		addrs[i] = s.listener.Addr().String()
	}

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < numServers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if sessions[idx] != nil {
				defer sessions[idx].Close()
			}

			conn, err := net.DialTimeout("tcp", addrs[idx], 10*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			if sessions[idx] != nil {
				conn.SetDeadline(time.Now().Add(30 * time.Second))
				sessions[idx].Initialize(conn)
			}
		}(i)
	}
	wg.Wait()
	return float64(time.Since(start).Microseconds())
}
