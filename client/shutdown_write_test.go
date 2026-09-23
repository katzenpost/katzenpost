package client

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
)

// recorderConn records writes and yields mid-write to widen the window
// for interleaving between two writeResponse callers.
type recorderConn struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *recorderConn) Write(p []byte) (int, error) {
	runtime.Gosched()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *recorderConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recorderConn) Close() error                     { return nil }
func (c *recorderConn) LocalAddr() net.Addr              { return nil }
func (c *recorderConn) RemoteAddr() net.Addr             { return nil }
func (c *recorderConn) SetDeadline(time.Time) error      { return nil }
func (c *recorderConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recorderConn) SetWriteDeadline(time.Time) error { return nil }

// TestWriteResponseConcurrentFraming checks concurrent writeResponse
// callers do not interleave their frames on the socket.
func TestWriteResponseConcurrentFraming(t *testing.T) {
	logBackend, err := log.New("", "error", false)
	require.NoError(t, err)
	rec := &recorderConn{}
	c := &incomingConn{
		conn:     rec,
		sendWake: make(chan struct{}, 1),
		doneCh:   make(chan struct{}),
		log:      logBackend.GetLogger("test"),
	}

	const writers = 8
	payload := bytes.Repeat([]byte{0xAB}, 512)
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- c.writeResponse(&Response{
				NewPKIDocumentEvent: &thin.NewPKIDocumentEvent{Payload: payload},
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	stream := rec.buf.Bytes()
	frames := 0
	for len(stream) > 0 {
		require.GreaterOrEqual(t, len(stream), 4, "truncated length prefix (frames interleaved)")
		n := binary.BigEndian.Uint32(stream[:4])
		stream = stream[4:]
		require.GreaterOrEqual(t, uint32(len(stream)), n, "frame shorter than its prefix (frames interleaved)")
		var resp thin.Response
		require.NoError(t, cbor.Unmarshal(stream[:n], &resp), "frame did not decode (frames interleaved)")
		stream = stream[n:]
		frames++
	}
	require.Equal(t, writers, frames)
}
