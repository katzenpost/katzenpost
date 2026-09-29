//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package wire

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/fuzz/seed"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

type fuzzWireAuthenticator struct{}

func (fuzzWireAuthenticator) IsPeerValid(*PeerCredentials) bool { return true }

type fuzzWireAddr struct{}

func (fuzzWireAddr) Network() string { return "fuzz" }
func (fuzzWireAddr) String() string  { return "fuzz" }

type fuzzWireConn struct {
	data []byte
	off  int
}

func (c *fuzzWireConn) Read(p []byte) (int, error) {
	if c.off >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(p, c.data[c.off:])
	c.off += n
	return n, nil
}

func (c *fuzzWireConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *fuzzWireConn) Close() error                     { return nil }
func (c *fuzzWireConn) LocalAddr() net.Addr              { return fuzzWireAddr{} }
func (c *fuzzWireConn) RemoteAddr() net.Addr             { return fuzzWireAddr{} }
func (c *fuzzWireConn) SetDeadline(time.Time) error      { return nil }
func (c *fuzzWireConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fuzzWireConn) SetWriteDeadline(time.Time) error { return nil }

func FuzzWireHandshakeResponder(f *testing.F) {
	scheme := kemschemes.ByName("x25519")
	_, priv, err := scheme.GenerateKeyPair()
	if err != nil {
		f.Fatal(err)
	}
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 3000, true, 5)
	cfg := &SessionConfig{
		KEMScheme:         scheme,
		Geometry:          g,
		Authenticator:     fuzzWireAuthenticator{},
		AdditionalData:    []byte("responder"),
		AuthenticationKey: priv,
		RandomReader:      rand.Reader,
	}

	msg1 := make([]byte, 1+scheme.PublicKeySize())
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0x03})
	f.Add(make([]byte, 1+scheme.PublicKeySize()))
	copy(msg1, prologue)
	f.Add(msg1)

	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		s, err := NewSession(cfg, false)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		conn := &fuzzWireConn{data: data}
		_ = s.Initialize(ctx, conn)
	})
}
