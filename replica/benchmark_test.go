// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

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

// benchReplicaServer simulates a replica server accepting incoming connections
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
				Authenticator:     &benchAuthenticator{},
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

// benchAuthenticator accepts all peers for benchmarking
type benchAuthenticator struct{}

func (a *benchAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	return true
}

// BenchmarkReplicaIncomingHandshake benchmarks incoming connections to replica
// (from couriers or other replicas)
func BenchmarkReplicaIncomingHandshake(b *testing.B) {
	concurrencyLevels := []int{1, 2, 5, 10}

	// Setup replica server
	serverLinkPubKey, serverLinkPrivKey, err := benchKEMScheme.GenerateKeyPair()
	if err != nil {
		b.Fatalf("failed to generate server link keypair: %v", err)
	}
	serverIdPubKey, _, err := benchSignScheme.GenerateKey()
	if err != nil {
		b.Fatalf("failed to generate server identity keypair: %v", err)
	}
	_ = serverLinkPubKey

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

	// Send logs to /dev/null to avoid stdout I/O overhead
	logBackend, err := log.New("/dev/null", "DEBUG", false)
	if err != nil {
		b.Fatalf("failed to create log backend: %v", err)
	}
	_ = logBackend

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("concurrent-%d", concurrency), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runReplicaIncomingHandshakes(b, listener.Addr().String(), concurrency)
				// Wait for all server-side handshakes to complete before next iteration
				connWg.Wait()
			}
		})
	}
}

func runReplicaIncomingHandshakes(b *testing.B, addr string, concurrency int) {
	var wg sync.WaitGroup
	var barrier sync.WaitGroup
	barrier.Add(1)

	durations := make([]time.Duration, concurrency)
	errors := make([]error, concurrency)

	for c := 0; c < concurrency; c++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// === SETUP (outside timed section) ===
			// Each connecting peer has its own link key
			_, peerLinkPrivKey, err := benchKEMScheme.GenerateKeyPair()
			if err != nil {
				errors[idx] = err
				return
			}

			// Peer identity hash (courier or another replica)
			peerIdPubKey, _, _ := benchSignScheme.GenerateKey()
			identityHash := hash.Sum256From(peerIdPubKey)

			// Pre-create session config and session object
			cfg := &wire.SessionConfig{
				KEMScheme:         benchKEMScheme,
				Geometry:          benchGeometry,
				Authenticator:     &benchAuthenticator{},
				AdditionalData:    identityHash[:],
				AuthenticationKey: peerLinkPrivKey,
				RandomReader:      rand.Reader,
			}

			session, err := wire.NewSession(cfg, true)
			if err != nil {
				errors[idx] = err
				return
			}
			defer session.Close()

			barrier.Wait() // All goroutines wait here

			// === TIMED SECTION: dial + handshake only ===
			start := time.Now()

			// Dial the replica
			conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
			if err != nil {
				errors[idx] = err
				durations[idx] = time.Since(start)
				return
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(30 * time.Second))
			if err = session.Initialize(conn); err != nil {
				errors[idx] = err
				durations[idx] = time.Since(start)
				return
			}

			durations[idx] = time.Since(start)
		}(c)
	}

	barrier.Done() // Release all at once!
	wg.Wait()

	// Report statistics
	var total time.Duration
	var minDur, maxDur time.Duration
	successCount := 0

	for i, d := range durations {
		if errors[i] != nil {
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
		b.ReportMetric(float64(avg.Microseconds()), "avg_µs")
		b.ReportMetric(float64(minDur.Microseconds()), "min_µs")
		b.ReportMetric(float64(maxDur.Microseconds()), "max_µs")
	}
}

// BenchmarkReplicaToReplicaHandshake benchmarks replica-to-replica connections
// (for replication traffic)
func BenchmarkReplicaToReplicaHandshake(b *testing.B) {
	numReplicas := 3

	// Setup multiple replica servers
	servers := make([]*benchReplicaServerInfo, numReplicas)

	for i := 0; i < numReplicas; i++ {
		linkPubKey, linkPrivKey, _ := benchKEMScheme.GenerateKeyPair()
		idPubKey, _, _ := benchSignScheme.GenerateKey()

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatalf("failed to start listener %d: %v", i, err)
		}

		s := &benchReplicaServerInfo{
			listener:    listener,
			linkPubKey:  linkPubKey,
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

	b.Run(fmt.Sprintf("replicas-%d-parallel", numReplicas), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			runParallelReplicaConnections(b, servers)
			// Wait for all server-side handshakes to complete before next iteration
			for _, s := range servers {
				s.connWg.Wait()
			}
		}
	})
}

type benchReplicaServerInfo struct {
	listener    net.Listener
	linkPubKey  kem.PublicKey
	linkPrivKey kem.PrivateKey
	idPubKey    sign.PublicKey
	done        chan struct{}
	wg          sync.WaitGroup
	connWg      sync.WaitGroup // Tracks in-flight handshakes
}

func runParallelReplicaConnections(b *testing.B, servers []*benchReplicaServerInfo) {
	_, replicaLinkPrivKey, _ := benchKEMScheme.GenerateKeyPair()
	replicaIdPubKey, _, _ := benchSignScheme.GenerateKey()
	identityHash := hash.Sum256From(replicaIdPubKey)

	var wg sync.WaitGroup
	start := time.Now()

	for _, s := range servers {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			cfg := &wire.SessionConfig{
				KEMScheme:         benchKEMScheme,
				Geometry:          benchGeometry,
				Authenticator:     &benchAuthenticator{},
				AdditionalData:    identityHash[:],
				AuthenticationKey: replicaLinkPrivKey,
				RandomReader:      rand.Reader,
			}
			session, _ := wire.NewSession(cfg, true)
			if session != nil {
				defer session.Close()
				conn.SetDeadline(time.Now().Add(30 * time.Second))
				session.Initialize(conn)
			}
		}(s.listener.Addr().String())
	}
	wg.Wait()
	b.ReportMetric(float64(time.Since(start).Microseconds()), "total_µs")
}
