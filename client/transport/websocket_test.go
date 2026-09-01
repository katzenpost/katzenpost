package transport

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeConn struct{ closed bool }

func (c *fakeConn) Close() error                     { c.closed = true; return nil }
func (c *fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *fakeConn) LocalAddr() net.Addr              { return nil }
func (c *fakeConn) RemoteAddr() net.Addr             { return nil }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func TestWebsocketListenerCloseIdempotent(t *testing.T) {
	l := &WebsocketListener{connections: make(chan net.Conn, 1), done: make(chan struct{})}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.Close()
		}()
	}
	wg.Wait()
}

func TestWebsocketListenerCloseDrainsAndReportsClosed(t *testing.T) {
	l := &WebsocketListener{connections: make(chan net.Conn, 1), done: make(chan struct{})}
	conn := &fakeConn{}
	l.connections <- conn
	require.NoError(t, l.Close())
	require.True(t, conn.closed, "queued conn should be closed on Close")
	_, err := l.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestWsListenConfigListenBindError(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()

	l, err := (&WsListenConfig{Address: "ws://" + occupied.Addr().String()}).Listen()
	require.Error(t, err)
	require.Nil(t, l)
}
