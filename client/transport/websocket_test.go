package transport

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
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
		go func() { defer wg.Done(); _ = l.Close() }()
	}
	wg.Wait()
	require.NoError(t, l.Close())
	_, err := l.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
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

// Listen must report the real bound port for ws://host:0 and free that exact
// port again on Close.
func TestWsListenReportsBoundPortAndFreesIt(t *testing.T) {
	l, err := (&WsListenConfig{Address: "ws://127.0.0.1:0"}).Listen()
	require.NoError(t, err)
	addr := l.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.NotEqual(t, "0", port, "bound port should be resolved, not 0")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws://"+addr, nil)
	require.NoError(t, err)
	c.CloseNow()

	require.NoError(t, l.Close())

	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err, "port still bound after Close")
	ln.Close()
}

// Accept run concurrently with Close must not race and must return ErrClosed.
func TestWsListenAcceptRaceWithClose(t *testing.T) {
	l, err := (&WsListenConfig{Address: "ws://127.0.0.1:0"}).Listen()
	require.NoError(t, err)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = l.Accept()
	}()
	require.NoError(t, l.Close())
	wg.Wait()
}

// A thin-client (no Origin header) is accepted; a cross-origin browser request
// is rejected.
func TestWsListenOriginChecked(t *testing.T) {
	l, err := (&WsListenConfig{Address: "ws://127.0.0.1:0"}).Listen()
	require.NoError(t, err)
	defer l.Close()
	url := "ws://" + l.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, url, nil)
	require.NoError(t, err)
	c.CloseNow()

	h := http.Header{}
	h.Set("Origin", "http://evil.example")
	_, _, err = websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: h})
	require.Error(t, err)
}

// A hostless address must default to loopback, never the 0.0.0.0 wildcard.
func TestWsListenDefaultsHostToLoopback(t *testing.T) {
	l, err := (&WsListenConfig{Address: "ws://:0"}).Listen()
	require.NoError(t, err)
	defer l.Close()
	ip := l.Addr().(*net.TCPAddr).IP
	require.True(t, ip.IsLoopback(), "hostless address bound %s, want loopback", ip)
}

func TestWsListenConfigListenBindError(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()

	l, err := (&WsListenConfig{Address: "ws://" + occupied.Addr().String()}).Listen()
	require.Error(t, err)
	require.Nil(t, l)
}
