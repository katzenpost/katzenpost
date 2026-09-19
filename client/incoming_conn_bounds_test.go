// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"encoding/binary"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
)

func newPKIReadyTestListener(t *testing.T) *listener {
	t.Helper()
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)
	cfg.Listen.Tcp.Address = "127.0.0.1:0"

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	client := &Client{cfg: cfg, logbackend: logBackend, log: logBackend.GetLogger("client")}
	doc := createMockPKIDocument(t)
	currentEpoch, _, _ := epochtime.Now()
	client.pki = &pki{c: client, log: logBackend.GetLogger("pki"), docs: sync.Map{}}
	client.pki.docs.Store(currentEpoch, &CachedDoc{Doc: doc, Blob: []byte{1}})

	l, err := NewListener(client, &Rates{}, make(chan *Request, 10), logBackend, nil)
	require.NoError(t, err)
	return l
}

type deadlineTrackingConn struct {
	net.Conn
	mu            sync.Mutex
	readDeadlines []time.Time
}

func (c *deadlineTrackingConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadlines = append(c.readDeadlines, t)
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *deadlineTrackingConn) deadlines() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time{}, c.readDeadlines...)
}

func TestRecvRequestBoundsTheBodyReadButNotThePrefixWait(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	tracked := &deadlineTrackingConn{Conn: serverConn}
	c := newIncomingConn(newGateTestListener(t), tracked)

	done := make(chan struct{})
	go func() {
		c.recvRequest()
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	require.Empty(t, tracked.deadlines(), "an idle thin client waiting to send its next request must not be timed out")

	lenPrefix := [4]byte{}
	binary.BigEndian.PutUint32(lenPrefix[:], 64)
	_, err := clientConn.Write(lenPrefix[:])
	require.NoError(t, err)

	require.Eventually(t, func() bool { return len(tracked.deadlines()) > 0 }, 2*time.Second, 10*time.Millisecond,
		"recvRequest never set a read deadline once the length prefix arrived")
	require.False(t, tracked.deadlines()[0].IsZero(), "the body read deadline must bound the read, not disable it")
}

func TestRecvRequestDoesNotAllocateTheDeclaredLengthUpFront(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	c := newIncomingConn(newGateTestListener(t), serverConn)

	go func() {
		lenPrefix := [4]byte{}
		binary.BigEndian.PutUint32(lenPrefix[:], thin.MaxMessageSize)
		clientConn.Write(lenPrefix[:])
		clientConn.Write([]byte{0})
		clientConn.Close()
	}()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := c.recvRequest()
	runtime.ReadMemStats(&after)

	require.Error(t, err)
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(1<<20),
		"a peer that declares a large frame and sends one byte made recvRequest allocate the declared length")
}

func TestListenerCapsConcurrentConnections(t *testing.T) {
	l := newPKIReadyTestListener(t)
	defer l.Shutdown()

	addr := l.listener.Addr()
	dial := func() net.Conn {
		conn, err := net.Dial(addr.Network(), addr.String())
		require.NoError(t, err)
		return conn
	}
	connCount := func() int {
		l.connsLock.RLock()
		defer l.connsLock.RUnlock()
		return len(l.conns)
	}
	settle := func() int {
		last, stable := -1, 0
		for i := 0; i < 60 && stable < 4; i++ {
			time.Sleep(50 * time.Millisecond)
			n := connCount()
			if n == last {
				stable++
			} else {
				stable = 0
			}
			last = n
		}
		return last
	}

	var conns []net.Conn
	for i := 0; i < 65; i++ {
		conns = append(conns, dial())
	}
	require.LessOrEqual(t, settle(), 64, "listener must cap concurrent thin-client connections")

	for _, c := range conns {
		c.Close()
	}
	require.Eventually(t, func() bool { return connCount() == 0 }, 5*time.Second, 20*time.Millisecond)

	again := dial()
	defer again.Close()
	require.Eventually(t, func() bool { return connCount() == 1 }, 5*time.Second, 20*time.Millisecond,
		"closed connections must give their slots back")
}
