package transport

import (
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWebsocketListenerCloseIdempotent verifies concurrent Close calls do
// not panic (double close of done) and that Accept reports closure.
func TestWebsocketListenerCloseIdempotent(t *testing.T) {
	l := &WebsocketListener{
		connections: make(chan net.Conn, 1),
		done:        make(chan struct{}),
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.Close()
		}()
	}
	wg.Wait()
	_, err := l.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

// TestWsListenConfigListenBindError verifies Listen surfaces a bind
// failure instead of returning a listener that never accepts.
func TestWsListenConfigListenBindError(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()

	l, err := (&WsListenConfig{Address: "ws://" + occupied.Addr().String()}).Listen()
	require.Error(t, err)
	require.Nil(t, l)
}
