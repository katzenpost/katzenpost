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
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katzenpost/hpqc/sign"
	"github.com/quic-go/quic-go"

	"github.com/katzenpost/katzenpost/core/retry"
	"github.com/katzenpost/katzenpost/core/wire"
)

// QuicConn wraps a conn and a single stream and implements net.Conn
type QuicConn struct {
	Stream *quic.Stream
	Conn   *quic.Conn

	streamReady   chan struct{}
	streamErr     error
	readMu        sync.Mutex
	writeMu       sync.Mutex
	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineSet   chan struct{}
	closed        atomic.Bool
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
	q := &QuicConn{
		Conn:        conn,
		Stream:      stream,
		streamReady: make(chan struct{}),
		deadlineSet: make(chan struct{}),
	}
	close(q.streamReady)
	return q
}

func newAcceptedQuicConn(conn *quic.Conn) *QuicConn {
	q := &QuicConn{
		Conn:        conn,
		streamReady: make(chan struct{}),
		deadlineSet: make(chan struct{}),
	}
	go q.acceptStream()
	return q
}

func (q *QuicConn) acceptStream() {
	ctx, cancel := context.WithTimeout(context.Background(), AcceptStreamTimeout)
	defer cancel()
	stream, err := q.Conn.AcceptStream(ctx)
	if err != nil {
		q.Conn.CloseWithError(0, "no stream opened")
	}
	q.deadlineMu.Lock()
	defer q.deadlineMu.Unlock()
	if err != nil {
		q.streamErr = err
	} else {
		stream.SetReadDeadline(q.readDeadline)
		stream.SetWriteDeadline(q.writeDeadline)
		q.Stream = stream
	}
	close(q.streamReady)
}

func (q *QuicConn) awaitStream(deadline *time.Time) error {
	for {
		q.deadlineMu.Lock()
		if q.Stream != nil || q.streamErr != nil {
			err := q.streamErr
			q.deadlineMu.Unlock()
			return err
		}
		until, deadlineSet := *deadline, q.deadlineSet
		q.deadlineMu.Unlock()
		if q.closed.Load() {
			return net.ErrClosed
		}
		if err := q.waitForStream(until, deadlineSet); err != nil {
			return err
		}
	}
}

func (q *QuicConn) waitForStream(until time.Time, deadlineSet <-chan struct{}) error {
	var expired <-chan time.Time
	if !until.IsZero() {
		wait := time.Until(until)
		if wait <= 0 {
			return os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case <-q.streamReady:
	case <-deadlineSet:
	case <-expired:
		return os.ErrDeadlineExceeded
	case <-q.Conn.Context().Done():
		<-q.streamReady
	}
	return nil
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
	return q.setDeadline(t, true, true)
}

// SetReadDeadline implements net.Conn
func (q *QuicConn) SetReadDeadline(t time.Time) error {
	return q.setDeadline(t, true, false)
}

// SetWriteDeadline implements net.Conn
func (q *QuicConn) SetWriteDeadline(t time.Time) error {
	return q.setDeadline(t, false, true)
}

func (q *QuicConn) setDeadline(t time.Time, read, write bool) error {
	q.deadlineMu.Lock()
	defer q.deadlineMu.Unlock()
	if q.closed.Load() {
		return net.ErrClosed
	}
	if read {
		q.readDeadline = t
	}
	if write {
		q.writeDeadline = t
	}
	if q.Stream == nil {
		q.wakeDeadlineWaiters()
		return nil
	}
	if read {
		if err := q.Stream.SetReadDeadline(t); err != nil {
			return err
		}
	}
	if write {
		return q.Stream.SetWriteDeadline(t)
	}
	return nil
}

func (q *QuicConn) wakeDeadlineWaiters() {
	close(q.deadlineSet)
	q.deadlineSet = make(chan struct{})
}

// Close implements net.Conn; all streams are closed.
func (q *QuicConn) Close() error {
	streamless, closing := q.markClosed()
	if !closing {
		return nil
	}
	if streamless {
		return q.Conn.CloseWithError(0, "")
	}
	q.writeMu.Lock()
	err := q.Stream.Close()
	q.writeMu.Unlock()
	go q.linger()
	return err
}

func (q *QuicConn) markClosed() (streamless, closing bool) {
	q.deadlineMu.Lock()
	defer q.deadlineMu.Unlock()
	if q.closed.Swap(true) {
		return false, false
	}
	q.wakeDeadlineWaiters()
	if q.Stream == nil {
		return true, true
	}
	q.Stream.SetDeadline(time.Now())
	return false, true
}

func (q *QuicConn) linger() {
	q.awaitInFlightRead()
	q.Stream.SetReadDeadline(time.Now().Add(closeLinger))
	io.Copy(io.Discard, q.Stream)
	q.Stream.CancelRead(0)
	q.Conn.CloseWithError(0, "")
}

func (q *QuicConn) awaitInFlightRead() {
	q.readMu.Lock()
	q.readMu.Unlock()
}

// Read implements net.Conn
func (q *QuicConn) Read(b []byte) (int, error) {
	q.readMu.Lock()
	defer q.readMu.Unlock()
	if q.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := 0, q.awaitStream(&q.readDeadline)
	if err == nil {
		n, err = q.Stream.Read(b)
	}
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
	n, err := 0, q.awaitStream(&q.writeDeadline)
	if err == nil {
		n, err = q.Stream.Write(b)
	}
	if err != nil && q.closed.Load() {
		err = net.ErrClosed
	}
	return n, err
}

// QuicListener implements net.Listener
type QuicListener struct {
	Listener *quic.Listener

	transport  *quic.Transport
	udpBuffers UDPBuffers
	connsMu    sync.Mutex
	conns      map[*quic.Conn]struct{}
	closed     bool
}

// AcceptStreamTimeout bounds how long a freshly-accepted QUIC connection has to
// open its stream. A legitimate peer opens it immediately after the handshake;
// a peer that completes the handshake and then never opens a stream would
// otherwise hold its connection open forever.
var AcceptStreamTimeout = 30 * time.Second

// Accept implements net.Listener. It accepts a QUIC connection and returns a
// QuicConn that implements net.Conn for its single stream, which is accepted
// on first use under that call's deadline.
func (l *QuicListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept(context.Background())
	if err != nil {
		return nil, &net.OpError{Op: "accept", Net: "quic", Addr: l.Listener.Addr(), Err: err}
	}
	settleHandshake(conn)
	if l.transport != nil && !l.track(conn) {
		conn.CloseWithError(0, "")
		return nil, &net.OpError{Op: "accept", Net: "quic", Addr: l.Listener.Addr(), Err: net.ErrClosed}
	}
	return newAcceptedQuicConn(conn), nil
}

func (l *QuicListener) track(conn *quic.Conn) bool {
	l.connsMu.Lock()
	defer l.connsMu.Unlock()
	if l.closed {
		return false
	}
	if l.conns == nil {
		l.conns = make(map[*quic.Conn]struct{})
	}
	l.conns[conn] = struct{}{}
	context.AfterFunc(conn.Context(), func() { l.untrack(conn) })
	return true
}

func (l *QuicListener) untrack(conn *quic.Conn) {
	l.connsMu.Lock()
	defer l.connsMu.Unlock()
	delete(l.conns, conn)
}

func (l *QuicListener) Addr() net.Addr {
	return l.Listener.Addr()
}

func (l *QuicListener) Close() error {
	err := l.Listener.Close()
	if l.transport == nil {
		return err
	}
	l.connsMu.Lock()
	if l.closed {
		l.connsMu.Unlock()
		return err
	}
	l.closed = true
	conns := slices.Collect(maps.Keys(l.conns))
	l.connsMu.Unlock()
	for _, conn := range conns {
		conn.CloseWithError(0, "")
	}
	l.transport.Close()
	l.transport.Conn.Close()
	return err
}

const statelessResetInfo = "katzenpost quic stateless reset"

func statelessResetKey(identityPrivateKey sign.PrivateKey) (*quic.StatelessResetKey, error) {
	identitySecret, err := identityPrivateKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	freshCopy, err := marshalBinaryReturnedAFreshCopy(identityPrivateKey, identitySecret)
	if err != nil {
		return nil, err
	}
	if freshCopy {
		defer clear(identitySecret)
	}
	derivedSecret, err := hkdf.Key(sha256.New, identitySecret, nil, statelessResetInfo, len(quic.StatelessResetKey{}))
	if err != nil {
		return nil, err
	}
	resetKey := quic.StatelessResetKey(derivedSecret)
	clear(derivedSecret)
	return &resetKey, nil
}

func marshalBinaryReturnedAFreshCopy(identityPrivateKey sign.PrivateKey, identitySecret []byte) (bool, error) {
	identitySecretAgain, err := identityPrivateKey.MarshalBinary()
	if err != nil {
		return false, err
	}
	freshCopy := len(identitySecret) > 0 && len(identitySecretAgain) > 0 && &identitySecret[0] != &identitySecretAgain[0]
	if freshCopy {
		clear(identitySecretAgain)
	}
	return freshCopy, nil
}

type CertificateSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

func ListenWithEpochKeys(host string, identityPrivateKey sign.PrivateKey, keys CertificateSource, opts *Options) (*QuicListener, error) {
	resetKey, err := statelessResetKey(identityPrivateKey)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		GetCertificate:   keys.GetCertificate,
		NextProtos:       opts.nextProtos(),
		CurvePreferences: opts.curvePreferences(),
	}
	transport := &quic.Transport{Conn: udpConn, StatelessResetKey: resetKey}
	opts.validateAddresses(transport)
	ql, err := transport.Listen(tlsConf, opts.quicConfig())
	if err != nil {
		transport.Close()
		udpConn.Close()
		return nil, err
	}
	return &QuicListener{Listener: ql, transport: transport, udpBuffers: readUDPBuffers(udpConn)}, nil
}

const KeepAlivePeriod = 3 * time.Minute

func Config() *quic.Config {
	return &quic.Config{
		KeepAlivePeriod:       ServerKeepAlivePeriod,
		MaxIdleTimeout:        wire.DefaultReadTimeout,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
	}
}

func GenerateTLSConfig() *tls.Config {
	_, tlsPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	certificate, err := epochCertificate(CurrentEpoch(), tlsPrivateKey)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*certificate},
		NextProtos:   []string{DefaultALPN},
	}
}

func LinkTransport(conn net.Conn) string {
	if _, ok := conn.(*QuicConn); ok {
		return "quic"
	}
	return "tcp"
}

func ConnectContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

var ErrQUICKeyMismatch = retry.ErrQUICKeyMismatch

const quicKeyHashPrefixSize = 4

type QUICKeyMismatchError struct {
	Presented []byte
	Expected  []byte
}

func (e *QUICKeyMismatchError) Error() string {
	expected := make([]string, 0, len(e.Expected)/sha256.Size+1)
	for rest := e.Expected; len(rest) > 0; rest = rest[min(len(rest), sha256.Size):] {
		expected = append(expected, hex.EncodeToString(rest[:min(len(rest), quicKeyHashPrefixSize)]))
	}
	presented := "nothing"
	if len(e.Presented) > 0 {
		presented = hex.EncodeToString(e.Presented[:min(len(e.Presented), quicKeyHashPrefixSize)])
	}
	return fmt.Sprintf("%v: presented %s, expected %s", ErrQUICKeyMismatch, presented, strings.Join(expected, " or "))
}

func (e *QUICKeyMismatchError) Unwrap() error {
	return ErrQUICKeyMismatch
}

func verifyQUICKeyHash(quicKeyHashes []byte) func(tls.ConnectionState) error {
	if len(quicKeyHashes) == 0 {
		return nil
	}
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return &QUICKeyMismatchError{Expected: quicKeyHashes}
		}
		presented := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if len(quicKeyHashes)%sha256.Size != 0 {
			return &QUICKeyMismatchError{Presented: presented[:], Expected: quicKeyHashes}
		}
		match := 0
		for pinned := quicKeyHashes; len(pinned) > 0; pinned = pinned[sha256.Size:] {
			match |= subtle.ConstantTimeCompare(presented[:], pinned[:sha256.Size])
		}
		if match != 1 {
			return &QUICKeyMismatchError{Presented: presented[:], Expected: quicKeyHashes}
		}
		return nil
	}
}

func DialURL(u *url.URL, ctx context.Context, dialFn func(ctx context.Context, network, address string) (net.Conn, error), quicKeyHashes []byte, opts *Options) (net.Conn, error) {
	switch u.Scheme {
	case "tcp", "onion":
		conn, err := dialFn(ctx, "tcp", u.Host)
		if err != nil {
			return nil, err
		} else {
			return conn, nil
		}
	case "quic":
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			VerifyConnection:   verifyQUICKeyHash(quicKeyHashes),
			NextProtos:         opts.nextProtos(),
			CurvePreferences:   opts.curvePreferences(),
		}
		cfg := opts.dialConfig()
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
			qconn.CloseWithError(0, "")
			return nil, err
		}
		return nil, err
	default:
		return nil, errors.New("Unsupported Scheme")
	}
}
