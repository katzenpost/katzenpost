package common

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/worker"
	kquic "github.com/katzenpost/katzenpost/quic"
	quic "github.com/quic-go/quic-go"
	qlogging "github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

var errHalted = errors.New("Halted")
var errDropped = errors.New("Dropped")
var zeroTime = (&time.Time{}).Unix()

type Transport interface {
	Accept(context.Context) (net.Conn, error)
	Dial(context.Context, net.Addr) (net.Conn, error)
	WritePacket(context.Context, []byte, net.Addr) (int, error)
	ReadPacket(context.Context, []byte) (int, net.Addr, error)
	Close() error
}

// this type implements net.PacketConn and sends and receives QUIC protocol messages.
// Method ProxyTo(conn) returns a net.Conn wrapping a QUIC Stream.
// Method ProxyFrom(conn) returns a net.Conn wrapping a QUIC Stream from the listener
// uses sends and receives QUIC messages exposes methods WriteMessage and ReadMessage that an application
type QUICProxyConn struct {
	sync.Mutex
	worker.Worker

	qcfg          *quic.Config
	tlsConf       *tls.Config
	localAddr     net.Addr
	remoteAddr    net.Addr
	readDeadline  time.Time
	writeDeadline time.Time

	// channels for payloads
	incoming chan *pkt
	outgoing chan *pkt
}

type pkt struct {
	payload []byte
	src     net.Addr
	dst     net.Addr
}

func UniqAddr(entropy []byte) net.Addr {
	return &uniqAddr{r: base64.StdEncoding.EncodeToString(entropy)}
}

// uniqAddr is a non-routable unique identifier to associate this connection with
type uniqAddr struct {
	r string
}

// Network() implements net.Addr
func (w *uniqAddr) Network() string {
	return "katzenpost"
}

// String() implements net.Addr
func (w *uniqAddr) String() string {
	if w.r == "" {
		ip := make([]byte, 20)
		if _, err := io.ReadFull(rand.Reader, ip); err != nil {
			panic(err)
		}
		w.r = base64.StdEncoding.EncodeToString(ip)
	}
	return w.r
}

type wc struct {
}

func (w *wc) Write(buf []byte) (int, error) {
	return os.Stdout.Write(buf)
}
func (w *wc) Close() error {
	return nil
}

// NewQUICProxyConn returns a
func NewQUICProxyConn(id []byte) *QUICProxyConn {
	return &QUICProxyConn{
		localAddr: UniqAddr(id),
		incoming:  make(chan *pkt, 1000),
		outgoing:  make(chan *pkt, 1000),
		tlsConf:   kquic.GenerateTLSConfig(),
		qcfg: &quic.Config{
			KeepAlivePeriod: 42 * time.Minute,
			HandshakeIdleTimeout: 42 * time.Minute,
			MaxIdleTimeout:  42 * time.Minute,
			Tracer: func(ctx context.Context, p qlogging.Perspective, connID quic.ConnectionID) *qlogging.ConnectionTracer {
				return qlog.NewConnectionTracer(&wc{}, p, connID)
			},
		},
	}
}

func (k *QUICProxyConn) Config() *quic.Config {
	return k.qcfg
}

func (k *QUICProxyConn) TLSConfig() *tls.Config {
	if k.tlsConf == nil {
		k.tlsConf = kquic.GenerateTLSConfig()
	}
	return k.tlsConf
}

func (k *QUICProxyConn) SetReadBuffer(bytes int) error {
	return nil
}

func (k *QUICProxyConn) SetWriteBuffer(bytes int) error {
	return nil
}

// WritePacket into QUICProxyConn
func (k *QUICProxyConn) WritePacket(ctx context.Context, p []byte, addr net.Addr) (int, error) {
	select {
	case <-ctx.Done():
		return 0, os.ErrDeadlineExceeded
	case k.incoming <- &pkt{payload: p, src: addr}:
	case <-k.HaltCh():
		return 0, io.EOF
		//default:
		//	// discard packet rather than block
		//	return 0, errDropped
	}
	return len(p), nil
}

// ReadPacket from QUICProxyConn
func (k *QUICProxyConn) ReadPacket(ctx context.Context, p []byte) (int, net.Addr, error) {
	select {
	case <-ctx.Done():
		return 0, nil, os.ErrDeadlineExceeded
	case pkt := <-k.outgoing:
		return copy(p, pkt.payload), pkt.dst, nil
	case <-k.HaltCh():
		return 0, nil, io.EOF
	}
}

// ReadFrom implements net.PacketConn
func (k *QUICProxyConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	k.Lock()
	if k.readDeadline.Unix() == zeroTime {
		k.Unlock()
		select {
		case pkt, ok := <-k.incoming:
			if ok {
				return copy(p, pkt.payload), pkt.src, nil
			} else {
				return 0, nil, io.EOF
			}
		case <-k.HaltCh():
			return 0, nil, errHalted
		}
	} else {
		after := k.readDeadline.Sub(time.Now())
		k.Unlock()
		select {
		case pkt := <-k.incoming:
			return copy(p, pkt.payload), pkt.src, nil
		case <-k.HaltCh():
			return 0, nil, errHalted
		case <-time.After(after):
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

// WriteTo implements net.PacketConn
func (k *QUICProxyConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {

	p2 := &pkt{payload: make([]byte, len(p)), dst: addr}
	copy(p2.payload, p)

	k.Lock()
	if k.writeDeadline.Unix() == zeroTime {
		k.Unlock()
		select {
		case k.outgoing <- p2:
			return len(p2.payload), nil
		case <-k.HaltCh():
			return 0, errHalted
		}
	} else {
		after := k.writeDeadline.Sub(time.Now())
		k.Unlock()
		select {
		case k.outgoing <- p2:
			return n, nil
		case <-time.After(after):
			return 0, os.ErrDeadlineExceeded
		case <-k.HaltCh():
			return 0, errHalted // XXX: io.EOF  ?
		}
	}
}

// Close implements net.PacketConn
func (k *QUICProxyConn) Close() error {
	k.Halt()
	return nil
}

// LocalAddr implements net.PacketConn
func (k *QUICProxyConn) LocalAddr() net.Addr {
	return k.localAddr
}

// SetDeadline implements net.PacketConn
func (k *QUICProxyConn) SetDeadline(t time.Time) error {
	k.Lock()
	defer k.Unlock()

	k.readDeadline = t
	k.writeDeadline = t
	return nil
}

// SetReadDeadline implements net.PacketConn
func (k *QUICProxyConn) SetReadDeadline(t time.Time) error {
	k.Lock()
	defer k.Unlock()

	k.readDeadline = t
	return nil
}

// SetWriteDeadline implements net.PacketConn
func (k *QUICProxyConn) SetWriteDeadline(t time.Time) error {
	k.Lock()
	defer k.Unlock()

	k.writeDeadline = t
	return nil
}

// Accept is for the Receiver side of Transport and returns a net.Conn after handshaking
func (k *QUICProxyConn) Accept(ctx context.Context) (net.Conn, error) {
	// start quic Listener
	l, err := quic.Listen(k, k.tlsConf, nil)
	if err != nil {
		return nil, err
	}

	for {
		select {
		case <-k.HaltCh():
			return nil, errHalted
		case <-ctx.Done():
			return nil, os.ErrDeadlineExceeded
		default:
		}
		c, err := l.Accept(ctx)
		if e, ok := err.(net.Error); ok && e.Timeout() {
			continue
		}
		if err != nil {
			return nil, err
		}
		k.remoteAddr = c.RemoteAddr()

		// accept stream
		s, err := c.AcceptStream(ctx)
		if e, ok := err.(net.Error); ok && e.Timeout() {
			continue
		}
		if err != nil {
			return nil, err
		}

		qc := &kquic.QuicConn{Stream: s, Conn: c}
		return qc, nil
	}
}

// Dial is for the Client side of Transport and returns a net.Conn after handshaking
func (k *QUICProxyConn) Dial(ctx context.Context, addr net.Addr) (net.Conn, error) {
	if addr == nil {
		return nil, errors.New("Dial() called with nil net.Addr")
	}
	k.remoteAddr = addr
	for {
		select {
		case <-k.HaltCh():
			return nil, errHalted
		case <-ctx.Done():
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("Cancelled")
		default:
		}

		c, err := quic.Dial(ctx, k, addr, k.tlsConf, k.Config())
		if e, ok := err.(net.Error); ok && e.Timeout() {
			continue
		}
		if err != nil {
			return nil, err
		}

		s, err := c.OpenStream()
		if e, ok := err.(net.Error); ok && e.Timeout() {
			continue
		}
		if err != nil {
			return nil, err
		}
		return &kquic.QuicConn{Stream: s, Conn: c}, nil
	}
}
