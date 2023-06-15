package common

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/katzenpost/katzenpost/core/worker"
	"gopkg.in/op/go-logging.v1"
	"github.com/google/gopacket/layers"
	"github.com/katzenpost/katzenpost/http/common"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	quic "github.com/quic-go/quic-go"
)

type Transport interface {
	Accept(context.Context) net.Conn
	Dial(context.Context) net.Conn
}

// this type implements net.PacketConn and sends and receives QUIC protocol messages.
// Method ProxyTo(conn) returns a net.Conn wrapping a QUIC Stream.
// Method ProxyFrom(conn) returns a net.Conn wrapping a QUIC Stream from the listener
// uses sends and receives QUIC messages exposes methods WriteMessage and ReadMessage that an application
type KatConn struct {
	worker.Worker

	log           *logging.Logger
	qcfg          *quic.Config
	tlsConf       *tls.Config
	localAddr     net.Addr
	remoteAddr    net.Addr
	readDeadline  time.Time
	writeDeadline time.Time

	// channels for payloads
	incoming chan []byte
	outgoing chan []byte
}

func NewKatConn(log *logging.Logger) *KatConn {
	ip := make([]byte, 4)
	io.ReadFull(rand.Reader, ip)
	addr := &net.UDPAddr{IP: net.IP(ip), Port: 80}
	log.Debugf("listening on %s", addr.String())

	return &KatConn{incoming:make(chan[]byte), outgoing:make(chan[]byte),
	tlsConf: common.GenerateTLSConfig(),
	/*
	cfg: &quic.Config{
		Tracer: func(ctx context.Context, log logging.Perspective, id ConnectionID) logging.ConnectionTracer {
		},
	},
	*/
	localAddr: addr, log:log}
}

func (k *KatConn) Config() *quic.Config {
	return k.qcfg
}

func (k *KatConn) TLSConfig() *tls.Config {
	if k.tlsConf == nil {
		k.tlsConf = common.GenerateTLSConfig()
	}
	return k.tlsConf
}

func (k *KatConn) SetReadBuffer(bytes int) error {
	k.log.Debugf("SetReadBuffer(%d)", bytes)
	return nil
}

func (k *KatConn) SetWriteBuffer(bytes int) error {
	k.log.Debugf("SetWriteBuffer(%d)", bytes)
	return nil
}

// WritePacket into KatConn
func (k *KatConn) WritePacket(p []byte) (int, error) {
	select {
	case k.incoming <- p:
	case <-k.HaltCh():
		return 0, errors.New("Halted")
	}
	return len(p), nil
}

// ReadPacket from KatConn
func (k *KatConn) ReadPacket(p []byte) (int, error) {
	select {
	case pkt := <-k.outgoing:
		return copy(p, pkt), nil
	case <-k.HaltCh():
		return 0, errors.New("Halted")
	//case <-time.After(k.readDeadline.Sub(time.Now())):
	//	return 0, os.ErrDeadlineExceeded
	}
}

// ReadFrom implements net.PacketConn
func (k *KatConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt := <-k.incoming:
		if len(p) != len(pkt) {
			k.log.Debugf("short read len(p): %d, len(pkt): %d", len(p), len(pkt))
		}
		return copy(p, pkt), k.remoteAddr, nil
	case <-k.HaltCh():
		k.log.Debugf("ReadFrom() halted")
		return 0, k.localAddr, errors.New("Halted")
	//case <-time.After(k.readDeadline.Sub(time.Now())):
	//	k.log.Debugf("ReadFrom() timed out reading")
	//	return 0, k.localAddr, os.ErrDeadlineExceeded
	}
}

type bleh int
func (b bleh) SetTruncated() {
}

// WriteTo implements net.PacketConn
func (k *KatConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	k.remoteAddr = addr
	if k.remoteAddr == nil {
		k.log.Debugf("nil remoteaddr, wtf")
	}
	l := layers.IPv4{}
	l.DecodeFromBytes(p, bleh(0))
	k.log.Debugf("got Addr: %s", l.DstIP)

	u := layers.UDP{}
	u.DecodeFromBytes(l.BaseLayer.Payload, bleh(0))
	k.log.Debugf("got DstPort: %s", u.DstPort)

	if len(p) > payloadSize {
		k.log.Debugf("short write len(p): %d, len(pkt): %d", len(p), payloadSize)
	}
	pkt := make([]byte, len(p))
	copy(pkt, p)
	select {
	case k.outgoing <- pkt:
		return len(pkt), nil
	//case <-time.After(k.writeDeadline.Sub(time.Now())):
	//	k.log.Debugf("WriteTo() timed out writing")
	//	return 0, errors.New("Timeout") // XXX: timeouterror
	case <-k.HaltCh():
		k.log.Debugf("WriteTo() halted")
		return 0, errors.New("Halted")
	}
	panic("wtf")
}

// Close implements net.PacketConn
func (k *KatConn) Close() error {
	return nil
}

// LocalAddr implements net.PacketConn
func (k *KatConn) LocalAddr() net.Addr {
	return k.localAddr
}

// SetDeadline implements net.PacketConn
func (k *KatConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implements net.PacketConn
func (k *KatConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements net.PacketConn
func (k *KatConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// Accept is for the Receiver side of Transport and returns a net.Conn after handshaking
func (k *KatConn) Accept(ctx context.Context) (net.Conn, error) {
	// start quic Listener
	l, err := quic.Listen(k, k.tlsConf, k.qcfg)
	if err != nil {
		return nil, err
	}

	for {
		select {
		case <-k.HaltCh():
			return nil, errors.New("Halted")
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
		k.log.Debugf("Accept remote: %s", c.RemoteAddr().String())

		// accept stream
		s, err := c.AcceptStream(ctx)
		panic("wtf")
		if e, ok := err.(net.Error); ok && e.Timeout() {
			continue
		}
		if err != nil {
			panic("WTF")
			return nil, err
		}

		qc := &common.QuicConn{Stream: s, Conn: c}
		return qc, nil
	}
}

// Dial is for the Client side of Transport and returns a net.Conn after handshaking
func (k *KatConn) Dial(ctx context.Context, addr net.Addr) (net.Conn, error) {
	k.remoteAddr = addr
	for {
		select {
		case <-k.HaltCh():
			return nil, errors.New("Halted")
		case <-ctx.Done():
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("Cancelled")
		default:
		}

		c, err := quic.Dial(ctx, k, k.remoteAddr, k.tlsConf, k.Config())
		if e, ok := err.(net.Error); ok && e.Timeout() {
			continue
		}
		if err != nil {
			panic(err)
			return nil, err
		}

		k.log.Debugf("LocalAddr(): %s", c.LocalAddr())
		s, err := c.OpenStream()
		if e, ok := err.(net.Error); ok && e.Timeout() {
			panic(err)
			continue
		}
		if err != nil {
			panic(err)
			return nil, err
		}
		return &common.QuicConn{Stream: s, Conn: c}, nil
	}
}
