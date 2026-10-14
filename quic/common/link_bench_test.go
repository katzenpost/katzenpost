// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package common

import (
	"context"
	"net"
	"net/url"
	"syscall"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

const (
	benchWireKEM      = "KYBER768-X25519"
	benchPacketLength = 3082
)

type acceptAnyPeer struct{}

func (acceptAnyPeer) IsPeerValid(*wire.PeerCredentials) bool { return true }

type benchLink struct {
	url        *url.URL
	quicPin    []byte
	clientKey  kem.PrivateKey
	geometry   *geo.Geometry
	handshaked chan struct{}
	received   chan struct{}
}

func benchSession(link *benchLink, key kem.PrivateKey, initiator bool) (*wire.Session, error) {
	ad := hash.Sum256From(key.Public())
	return wire.NewSession(&wire.SessionConfig{
		KEMScheme:         kemschemes.ByName(benchWireKEM),
		Geometry:          link.geometry,
		Authenticator:     acceptAnyPeer{},
		AdditionalData:    ad[:],
		AuthenticationKey: key,
		RandomReader:      rand.Reader,
	}, initiator)
}

func serveBenchLinks(link *benchLink, l net.Listener, serverKey kem.PrivateKey) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetNoDelay(true)
			}
			s, err := benchSession(link, serverKey, false)
			if err != nil {
				return
			}
			defer s.Close()
			if s.Initialize(context.Background(), conn) != nil {
				return
			}
			link.handshaked <- struct{}{}
			for {
				if _, err := s.RecvCommand(context.Background()); err != nil {
					return
				}
				link.received <- struct{}{}
			}
		}()
	}
}

func newBenchLink(b *testing.B, quicLink bool) *benchLink {
	scheme := kemschemes.ByName(benchWireKEM)
	_, serverKey, err := scheme.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	_, clientKey, err := scheme.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	link := &benchLink{
		clientKey:  clientKey,
		geometry:   geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5),
		handshaked: make(chan struct{}, 1),
		received:   make(chan struct{}, 64),
	}
	if link.geometry.PacketLength != benchPacketLength {
		b.Fatalf("geometry packet length %d, want %d", link.geometry.PacketLength, benchPacketLength)
	}
	var l net.Listener
	if quicLink {
		keys := newTestEpochKeys(b, b.TempDir(), newEpochClock(CurrentEpoch()))
		ql := listenWithEpochKeys(b, keys)
		link.quicPin, err = keys.Hashes(CurrentEpoch())
		if err != nil {
			b.Fatal(err)
		}
		link.url = &url.URL{Scheme: "quic", Host: ql.Addr().String()}
		l = ql
	} else {
		tl, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { tl.Close() })
		link.url = &url.URL{Scheme: "tcp", Host: tl.Addr().String()}
		l = tl
	}
	go serveBenchLinks(link, l, serverKey)
	return link
}

func (link *benchLink) dial(b *testing.B) *wire.Session {
	conn, err := DialURL(link.url, context.Background(), (&net.Dialer{}).DialContext, link.quicPin, nil)
	if err != nil {
		b.Fatal(err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}
	s, err := benchSession(link, link.clientKey, true)
	if err != nil {
		b.Fatal(err)
	}
	if err := s.Initialize(context.Background(), conn); err != nil {
		b.Fatal(err)
	}
	<-link.handshaked
	return s
}

func processCPU(b *testing.B) time.Duration {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		b.Fatal(err)
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

func benchmarkLinkHandshake(b *testing.B, quicLink bool) {
	link := newBenchLink(b, quicLink)
	b.ReportAllocs()
	b.ResetTimer()
	cpu := processCPU(b)
	for i := 0; i < b.N; i++ {
		link.dial(b).Close()
	}
	b.ReportMetric(float64(processCPU(b)-cpu)/float64(b.N), "cpu-ns/op")
}

func benchmarkLinkTransfer(b *testing.B, quicLink bool) {
	link := newBenchLink(b, quicLink)
	s := link.dial(b)
	defer s.Close()
	sent := make(chan error, 1)
	b.SetBytes(benchPacketLength)
	b.ReportAllocs()
	b.ResetTimer()
	packet := make([]byte, benchPacketLength)
	cpu := processCPU(b)
	go func() {
		for i := 0; i < b.N; i++ {
			if err := s.SendCommand(context.Background(), &commands.SendPacket{SphinxPacket: packet, Cmds: s.GetCommands()}); err != nil {
				sent <- err
				return
			}
		}
		sent <- nil
	}()
	pending := sent
	for received := 0; received < b.N || pending != nil; {
		select {
		case <-link.received:
			received++
		case err := <-pending:
			if err != nil {
				b.Fatal(err)
			}
			pending = nil
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(processCPU(b)-cpu)/float64(b.N), "cpu-ns/msg")
}

func BenchmarkLinkHandshakeTCP(b *testing.B) { benchmarkLinkHandshake(b, false) }

func BenchmarkLinkHandshakeQUIC(b *testing.B) { benchmarkLinkHandshake(b, true) }

func BenchmarkLinkTransferTCP(b *testing.B) { benchmarkLinkTransfer(b, false) }

func BenchmarkLinkTransferQUIC(b *testing.B) { benchmarkLinkTransfer(b, true) }
