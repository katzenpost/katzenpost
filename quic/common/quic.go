// quic.go - Katzenpost voting authority quic helper methods.
// Copyright (C) 2023  Masala.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package common contains things shared by client and server
package common

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/katzenpost/katzenpost/core/wire"
)

// QuicConn wraps a conn and a single stream and implements net.Conn
type QuicConn struct {
	Stream *quic.Stream
	Conn   *quic.Conn

	readMu     sync.Mutex
	writeMu    sync.Mutex
	deadlineMu sync.Mutex
	closed     atomic.Bool
}

const closeLinger = 2 * time.Second

// NewQuicConn creates a new QuicConn with the provided connection and stream.
// Both conn and stream must be non-nil.
func NewQuicConn(conn *quic.Conn, stream *quic.Stream) *QuicConn {
	if conn == nil {
		panic("QuicConn requires a non-nil connection")
	}
	if stream == nil {
		panic("QuicConn requires a non-nil stream")
	}
	return &QuicConn{
		Conn:   conn,
		Stream: stream,
	}
}

// LocalAddr implements net.Conn
func (q *QuicConn) LocalAddr() net.Addr {
	return q.Conn.LocalAddr()
}

// RemoteAddr implements net.Conn
func (q *QuicConn) RemoteAddr() net.Addr {
	return q.Conn.RemoteAddr()
}

// SetDeadline implements net.Conn
func (q *QuicConn) SetDeadline(t time.Time) error {
	q.deadlineMu.Lock()
	defer q.deadlineMu.Unlock()
	if q.closed.Load() {
		return net.ErrClosed
	}
	return q.Stream.SetDeadline(t)
}

// SetReadDeadline implements net.Conn
func (q *QuicConn) SetReadDeadline(t time.Time) error {
	q.deadlineMu.Lock()
	defer q.deadlineMu.Unlock()
	if q.closed.Load() {
		return net.ErrClosed
	}
	return q.Stream.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn
func (q *QuicConn) SetWriteDeadline(t time.Time) error {
	q.deadlineMu.Lock()
	defer q.deadlineMu.Unlock()
	if q.closed.Load() {
		return net.ErrClosed
	}
	return q.Stream.SetWriteDeadline(t)
}

// Close implements net.Conn; all streams are closed.
func (q *QuicConn) Close() error {
	if !q.markClosed() {
		return nil
	}
	q.writeMu.Lock()
	err := q.Stream.Close()
	q.writeMu.Unlock()
	go q.linger()
	return err
}

func (q *QuicConn) markClosed() bool {
	q.deadlineMu.Lock()
	defer q.deadlineMu.Unlock()
	if q.closed.Swap(true) {
		return false
	}
	q.Stream.SetDeadline(time.Now())
	return true
}

func (q *QuicConn) linger() {
	q.readMu.Lock()
	defer q.readMu.Unlock()
	q.Stream.SetReadDeadline(time.Now().Add(closeLinger))
	io.Copy(io.Discard, q.Stream)
	q.Stream.CancelRead(0)
	q.Conn.CloseWithError(0, "")
}

// Read implements net.Conn
func (q *QuicConn) Read(b []byte) (int, error) {
	q.readMu.Lock()
	defer q.readMu.Unlock()
	if q.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := q.Stream.Read(b)
	if err != nil && q.closed.Load() {
		err = net.ErrClosed
	}
	return n, err
}

// Write implements net.Conn
func (q *QuicConn) Write(b []byte) (int, error) {
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	if q.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := q.Stream.Write(b)
	if err != nil && q.closed.Load() {
		err = net.ErrClosed
	}
	return n, err
}

// QuicListener implements net.Listener
type QuicListener struct {
	Listener *quic.Listener
}

// AcceptStreamTimeout bounds how long a freshly-accepted QUIC connection has to
// open its stream. A legitimate peer opens it immediately after the handshake;
// a peer that completes the handshake and then never opens a stream would
// otherwise block AcceptStream (and thus the whole accept loop) forever.
var AcceptStreamTimeout = 30 * time.Second

// Accept implements net.Listener. It accepts a QUIC connection and its single
// stream, returning a QuicConn that implements net.Conn for that stream.
//
// AcceptStream is bounded by AcceptStreamTimeout: a connection that completes
// the QUIC handshake but does not open a stream in time is dropped and the loop
// moves on to the next connection, so one silent peer cannot wedge the listener.
func (l *QuicListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept(context.Background())
		if err != nil {
			return nil, &net.OpError{Op: "accept", Net: "quic", Addr: l.Listener.Addr(), Err: err}
		}
		streamCtx, cancel := context.WithTimeout(context.Background(), AcceptStreamTimeout)
		stream, err := conn.AcceptStream(streamCtx)
		cancel()
		if err != nil {
			conn.CloseWithError(0, "no stream opened")
			continue
		}
		return NewQuicConn(conn, stream), nil
	}
}

func (l *QuicListener) Addr() net.Addr {
	return l.Listener.Addr()
}

func (l *QuicListener) Close() error {
	return l.Listener.Close()
}

const KeepAlivePeriod = 3 * time.Minute

func Config() *quic.Config {
	return &quic.Config{KeepAlivePeriod: KeepAlivePeriod, MaxIdleTimeout: wire.DefaultReadTimeout}
}

// Setup a bare-bones TLS config for the server
func GenerateTLSConfig() *tls.Config {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		panic(err)
	}
	pkb, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: pkb})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	// ALPN (NextProtos) is externally visible as part of the QUIC TLS
	// handshake, in the client/server hello, so pick a common protocol
	// rather than something uniquely fingerprintable to katzenpost.
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}, NextProtos: []string{http3.NextProtoH3}}
}

func DialURL(u *url.URL, ctx context.Context, dialFn func(ctx context.Context, network, address string) (net.Conn, error)) (net.Conn, error) {
	switch u.Scheme {
	case "tcp", "onion":
		// XXX: make sure to use the supplied dialer for proxy users
		conn, err := dialFn(ctx, "tcp", u.Host)
		if err != nil {
			return nil, err
		} else {
			return conn, nil
		}
	case "quic":
		// http/3 quic connector
		// XXX: will need to add the TLS certificate
		// fingerprint to the authority configuration
		// or obtain valid CA-signed certificates for
		// the authorities.
		pool, err := x509.SystemCertPool()
		if err != nil {
			panic(err)
		}
		tlsConf := &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: true, // XXX
			// ALPN is externally visible as part of the client/server hello,
			// so pick a common protocol rather than something fingerprintable.
			NextProtos: []string{http3.NextProtoH3},
		}
		cfg := Config()
		if deadline, ok := ctx.Deadline(); ok {
			cfg.HandshakeIdleTimeout = max(time.Until(deadline), 0)
		}
		qconn, err := quic.DialAddr(ctx, u.Host, tlsConf, cfg)
		if err == nil {
			// open a quic stream
			stream, err := qconn.OpenStream()
			if err == nil {
				// wrap the stream and conn to implement net.Conn
				return NewQuicConn(qconn, stream), nil
			}
			return nil, err
		}
		return nil, err
	default:
		return nil, errors.New("Unsupported Scheme")
	}
}
