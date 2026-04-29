// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pki

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

	vClient "github.com/katzenpost/katzenpost/authority/voting/client"
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

// benchDirauthServer simulates a dirauth server accepting handshakes
func benchDirauthServer(listener net.Listener, serverLinkPrivKey kem.PrivateKey, serverIdPubKey sign.PublicKey, done chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

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

		go func(c net.Conn) {
			defer c.Close()

			identityHash := hash.Sum256From(serverIdPubKey)
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

// acceptAllAuthenticator accepts all peers
type acceptAllAuthenticator struct{}

func (a *acceptAllAuthenticator) IsPeerValid(creds *wire.PeerCredentials) bool {
	return true
}

// BenchmarkPKIClientHandshakeConcurrency benchmarks the mix server's PKI client
// connecting to dirauth servers concurrently (simulates epoch transitions)
func BenchmarkPKIClientHandshakeConcurrency(b *testing.B) {
	concurrencyLevels := []int{1, 2, 5, 10}

	// Setup dirauth server
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
	serverWg.Add(1)
	go benchDirauthServer(listener, serverLinkPrivKey, serverIdPubKey, done, &serverWg)
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

	// Create authority config (like mix server does)
	peer := &config.Authority{
		Identifier:         "bench-dirauth",
		IdentityPublicKey:  serverIdPubKey,
		LinkPublicKey:      serverLinkPubKey,
		PKISignatureScheme: benchSignScheme.Name(),
		WireKEMScheme:      benchKEMScheme.Name(),
		Addresses:          []string{fmt.Sprintf("tcp://%s", listener.Addr().String())},
	}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("concurrent-%d", concurrency), func(b *testing.B) {
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				runPKIClientConcurrentHandshakes(b, logBackend, peer, concurrency)
			}
		})
	}
}

func runPKIClientConcurrentHandshakes(b *testing.B, logBackend *log.Backend, peer *config.Authority, concurrency int) {
	var wg sync.WaitGroup
	var barrier sync.WaitGroup
	barrier.Add(1)

	durations := make([]time.Duration, concurrency)
	errors := make([]error, concurrency)

	for c := 0; c < concurrency; c++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// Each mix node has its own link key
			_, clientLinkPrivKey, err := benchKEMScheme.GenerateKeyPair()
			if err != nil {
				errors[idx] = err
				return
			}

			cfg := &vClient.Config{
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

			conn := newBenchConnector(cfg, logBackend)

			barrier.Wait() // All goroutines wait here

			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			c, err := conn.initSession(ctx, clientLinkPrivKey, peer)
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

// newBenchConnector creates a connector for benchmarking
// This wraps the vClient.New to get access to initSession
func newBenchConnector(cfg *vClient.Config, logBackend *log.Backend) *benchConnector {
	return &benchConnector{
		cfg:        cfg,
		logBackend: logBackend,
	}
}

type benchConnector struct {
	cfg        *vClient.Config
	logBackend *log.Backend
}

type benchSession struct {
	conn    net.Conn
	session *wire.Session
}

func (c *benchConnector) initSession(ctx context.Context, linkKey kem.PrivateKey, peer *config.Authority) (*benchSession, error) {
	// Dial the peer
	addr := peer.Addresses[0]
	// Strip tcp:// prefix
	if len(addr) > 6 && addr[:6] == "tcp://" {
		addr = addr[6:]
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	// Perform handshake
	identityHash := hash.Sum256From(c.cfg.LinkKey.Public())
	sessionCfg := &wire.SessionConfig{
		KEMScheme:         c.cfg.KEMScheme,
		Geometry:          c.cfg.Geo,
		Authenticator:     &acceptAllAuthenticator{},
		AdditionalData:    identityHash[:],
		AuthenticationKey: linkKey,
		RandomReader:      rand.Reader,
	}

	session, err := wire.NewPKISession(sessionCfg, true)
	if err != nil {
		conn.Close()
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err = session.Initialize(conn); err != nil {
		session.Close()
		conn.Close()
		return nil, err
	}

	return &benchSession{conn: conn, session: session}, nil
}

// BenchmarkMultipleDirauthHandshake benchmarks connecting to multiple dirauth servers
// (simulates mix server fetching from multiple authorities for consensus)
func BenchmarkMultipleDirauthHandshake(b *testing.B) {
	numAuthorities := 3

	// Setup multiple dirauth servers
	type dirauthServer struct {
		listener    net.Listener
		linkPubKey  kem.PublicKey
		linkPrivKey kem.PrivateKey
		idPubKey    sign.PublicKey
		done        chan struct{}
		wg          sync.WaitGroup
	}
	servers := make([]*dirauthServer, numAuthorities)
	peers := make([]*config.Authority, numAuthorities)

	for i := 0; i < numAuthorities; i++ {
		linkPubKey, linkPrivKey, _ := benchKEMScheme.GenerateKeyPair()
		idPubKey, _, _ := benchSignScheme.GenerateKey()

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatalf("failed to start listener %d: %v", i, err)
		}

		s := &dirauthServer{
			listener:    listener,
			linkPubKey:  linkPubKey,
			linkPrivKey: linkPrivKey,
			idPubKey:    idPubKey,
			done:        make(chan struct{}),
		}
		s.wg.Add(1)
		go benchDirauthServer(listener, linkPrivKey, idPubKey, s.done, &s.wg)
		servers[i] = s

		peers[i] = &config.Authority{
			Identifier:         fmt.Sprintf("dirauth-%d", i),
			IdentityPublicKey:  idPubKey,
			LinkPublicKey:      linkPubKey,
			PKISignatureScheme: benchSignScheme.Name(),
			WireKEMScheme:      benchKEMScheme.Name(),
			Addresses:          []string{fmt.Sprintf("tcp://%s", listener.Addr().String())},
		}
	}
	defer func() {
		for _, s := range servers {
			close(s.done)
			s.listener.Close()
			s.wg.Wait()
		}
	}()

	// Send logs to /dev/null to avoid stdout I/O overhead
	// while still exercising the full DEBUG logging code paths
	logBackend, err := log.New("/dev/null", "DEBUG", false)
	if err != nil {
		b.Fatalf("failed to create log backend: %v", err)
	}

	b.Run(fmt.Sprintf("authorities-%d-sequential", numAuthorities), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			runSequentialDirauthFetch(b, logBackend, peers)
		}
	})

	b.Run(fmt.Sprintf("authorities-%d-parallel", numAuthorities), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			runParallelDirauthFetch(b, logBackend, peers)
		}
	})
}

func runSequentialDirauthFetch(b *testing.B, logBackend *log.Backend, peers []*config.Authority) {
	_, clientLinkPrivKey, _ := benchKEMScheme.GenerateKeyPair()

	start := time.Now()
	for _, peer := range peers {
		cfg := &vClient.Config{
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
		conn := newBenchConnector(cfg, logBackend)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		c, err := conn.initSession(ctx, clientLinkPrivKey, peer)
		cancel()
		if err != nil {
			b.Logf("Sequential fetch failed: %v", err)
			continue
		}
		c.conn.Close()
	}
	b.ReportMetric(float64(time.Since(start).Microseconds()), "total_µs")
}

func runParallelDirauthFetch(b *testing.B, logBackend *log.Backend, peers []*config.Authority) {
	_, clientLinkPrivKey, _ := benchKEMScheme.GenerateKeyPair()

	var wg sync.WaitGroup
	start := time.Now()

	for _, peer := range peers {
		wg.Add(1)
		go func(p *config.Authority) {
			defer wg.Done()
			cfg := &vClient.Config{
				KEMScheme:           benchKEMScheme,
				PKISignatureScheme:  benchSignScheme,
				LinkKey:             clientLinkPrivKey,
				LogBackend:          logBackend,
				Authorities:         []*config.Authority{p},
				Geo:                 benchGeometry,
				DialTimeoutSec:      10,
				HandshakeTimeoutSec: 30,
				ResponseTimeoutSec:  30,
			}
			conn := newBenchConnector(cfg, logBackend)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			c, err := conn.initSession(ctx, clientLinkPrivKey, p)
			cancel()
			if err != nil {
				return
			}
			c.conn.Close()
		}(peer)
	}
	wg.Wait()
	b.ReportMetric(float64(time.Since(start).Microseconds()), "total_µs")
}
