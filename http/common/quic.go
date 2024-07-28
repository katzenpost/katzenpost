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
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// QuicConn wraps a conn and a single stream and implements net.Conn
type QuicConn struct {
	Stream quic.Stream
	Conn   quic.Connection
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
	return q.Stream.SetDeadline(t)
}

// SetReadDeadline implements net.Conn
func (q *QuicConn) SetReadDeadline(t time.Time) error {
	return q.Stream.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn
func (q *QuicConn) SetWriteDeadline(t time.Time) error {
	return q.Stream.SetWriteDeadline(t)
}

// Close implements net.Conn; all streams are closed.
func (q *QuicConn) Close() error {
	return q.Stream.Close()
}

// Read implements net.Conn
func (q *QuicConn) Read(b []byte) (n int, err error) {
	return q.Stream.Read(b)
}

// Write implements net.Conn
func (q *QuicConn) Write(b []byte) (n int, err error) {
	return q.Stream.Write(b)
}

// QuicListener implements net.Listener
type QuicListener struct {
	Listener *quic.Listener
}

// Accept implements net.Listener. It starts a single QUIC Stream and returns a
// QuicConn that implements net.Conn for this single Stream.
func (l *QuicListener) Accept() (net.Conn, error) {
	ctx := context.Background()
	conn, err := l.Listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &QuicConn{Conn: conn, Stream: stream}, nil
}

func (l *QuicListener) Addr() net.Addr {
	return l.Listener.Addr()
}

func (l *QuicListener) Close() error {
	return l.Listener.Close()
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
	case "tcp":
		// XXX: make sure to use the supplied dialer for proxy users
		conn, err := dialFn(ctx, "tcp", u.Host)
		if err != nil {
			return nil, err
		} else {
			return conn, nil
		}
	case "http":
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
		qconn, err := quic.DialAddr(ctx, u.Host, tlsConf, nil)
		if err == nil {
			// open a quic stream
			stream, err := qconn.OpenStream()
			if err == nil {
				// wrap the stream and conn to implement net.Conn
				return &QuicConn{Stream: stream, Conn: qconn}, nil
			}
			return nil, err
		}
		return nil, err
	default:
		return nil, errors.New("Unsupported Scheme")
	}
}
