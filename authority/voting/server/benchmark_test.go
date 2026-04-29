// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

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

// benchDirauthServer runs a mock dirauth server that accepts and performs handshakes
// connWg tracks in-flight connection handshakes to prevent iteration overlap
func benchDirauthServer(listener net.Listener, serverLinkPrivKey kem.PrivateKey, serverIdPubKey sign.PublicKey, authorizedMixes map[[hash.HashSize]byte]string, done chan struct{}, wg *sync.WaitGroup, connWg *sync.WaitGroup) {
	defer wg.Done()

	// Pre-compute identity hash once
	identityHash := hash.Sum256From(serverIdPubKey)
	auth := &benchAuthenticator{authorizedMixes: authorizedMixes}

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

// benchAuthenticator simulates IsPeerValid with map lookups like real dirauth
type benchAuthenticator struct {
	authorizedMixes map[[hash.HashSize]byte]string
}

func (a *benchAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	// Simulate client connection (no additional data)
	if len(creds.AdditionalData) == 0 {
		return true
	}

	// Simulate mix authentication with map lookup
	if len(creds.AdditionalData) == hash.HashSize {
		pk := [hash.HashSize]byte{}
		copy(pk[:], creds.AdditionalData[:hash.HashSize])
		_, isMix := a.authorizedMixes[pk]
		return isMix
	}

	return false
}

// BenchmarkDirauthHandshakeConcurrency benchmarks dirauth handshake under concurrent load
func BenchmarkDirauthHandshakeConcurrency(b *testing.B) {
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

	// Create authorized mixes map (simulating the real dirauth state)
	authorizedMixes := make(map[[hash.HashSize]byte]string)
	clientKeys := make([]kem.PrivateKey, 50)
	clientIdKeys := make([]sign.PublicKey, 50)
	for i := 0; i < 50; i++ {
		_, clientLinkPrivKey, _ := benchKEMScheme.GenerateKeyPair()
		clientIdPubKey, _, _ := benchSignScheme.GenerateKey()
		clientKeys[i] = clientLinkPrivKey
		clientIdKeys[i] = clientIdPubKey
		idHash := hash.Sum256From(clientIdPubKey)
		authorizedMixes[idHash] = fmt.Sprintf("mix-%d", i)
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
	go benchDirauthServer(listener, serverLinkPrivKey, serverIdPubKey, authorizedMixes, done, &serverWg, &connWg)
	defer func() {
		close(done)
		serverWg.Wait()
	}()

	serverAddr := listener.Addr().String()

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("concurrent-%d", concurrency), func(b *testing.B) {
			// Accumulators for aggregating stats across iterations
			var totalAvg, totalMin, totalMax float64
			var totalCount, totalErrors int

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				stats := runDirauthConcurrentHandshakes(serverAddr, clientKeys, clientIdKeys, concurrency)
				totalAvg += stats.avgUs
				totalMin += stats.minUs
				totalMax += stats.maxUs
				totalCount += stats.count
				totalErrors += stats.errors

				// Wait for server-side handshakes to complete before next iteration
				connWg.Wait()
			}

			// Report aggregated metrics (averaged over b.N iterations)
			if b.N > 0 && totalCount > 0 {
				b.ReportMetric(totalAvg/float64(b.N), "avg_us")
				b.ReportMetric(totalMin/float64(b.N), "min_us")
				b.ReportMetric(totalMax/float64(b.N), "max_us")
			}
		})
	}
}

func runDirauthConcurrentHandshakes(serverAddr string, clientKeys []kem.PrivateKey, clientIdKeys []sign.PublicKey, concurrency int) handshakeStats {
	var wg sync.WaitGroup
	var barrier sync.WaitGroup
	barrier.Add(1)

	durations := make([]time.Duration, concurrency)
	errors := make([]error, concurrency)

	for c := 0; c < concurrency; c++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// Use pre-generated client keys
			clientLinkPrivKey := clientKeys[idx%len(clientKeys)]
			clientIdPubKey := clientIdKeys[idx%len(clientIdKeys)]

			barrier.Wait() // All goroutines wait here

			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Dial and perform handshake
			var d net.Dialer
			conn, err := d.DialContext(ctx, "tcp", serverAddr)
			if err != nil {
				errors[idx] = err
				return
			}
			defer conn.Close()

			identityHash := hash.Sum256From(clientIdPubKey)
			cfg := &wire.SessionConfig{
				KEMScheme:         benchKEMScheme,
				Geometry:          benchGeometry,
				Authenticator:     &acceptAllAuthenticator{},
				AdditionalData:    identityHash[:],
				AuthenticationKey: clientLinkPrivKey,
				RandomReader:      rand.Reader,
			}
			session, err := wire.NewPKISession(cfg, true)
			if err != nil {
				errors[idx] = err
				return
			}
			defer session.Close()

			conn.SetDeadline(time.Now().Add(30 * time.Second))
			err = session.Initialize(conn)
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

// acceptAllAuthenticator accepts all peers (for client-side benchmarks)
type acceptAllAuthenticator struct{}

func (a *acceptAllAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	return true
}
