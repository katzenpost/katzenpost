//go:build !windows
// +build !windows

package client

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/stretchr/testify/require"
)

// getFreePort returns a free port by binding to :0 and then closing the listener
func getFreePort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func TestDaemonStartStop(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	// Use a dynamic port to avoid conflicts
	port, err := getFreePort()
	require.NoError(t, err)
	cfg.ListenAddress = fmt.Sprintf("localhost:%d", port)

	d, err := NewDaemon(cfg)
	require.NoError(t, err)

	err = d.Start()
	require.NoError(t, err)

	time.Sleep(time.Second * 3)

	d.Shutdown()
}

func TestDaemonStartsWithoutConsensus(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	port, err := getFreePort()
	require.NoError(t, err)
	cfg.ListenAddress = fmt.Sprintf("localhost:%d", port)

	d, err := NewDaemon(cfg)
	require.NoError(t, err)

	err = d.Start()
	require.NoError(t, err, "Daemon.Start() should succeed even without consensus")

	conn, err := net.DialTimeout("tcp", cfg.ListenAddress, time.Second)
	require.NoError(t, err, "Should be able to connect to listener without consensus")
	conn.Close()

	d.Shutdown()
}

func TestListenerAcceptsConnectionWithoutPKIDoc(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	cfg.ListenAddress = "127.0.0.1:0"

	client := &Client{
		cfg: cfg,
		pki: nil,
	}

	rates := &Rates{}
	egressCh := make(chan *Request, 10)

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	listener, err := NewListener(client, rates, egressCh, logBackend, nil)
	require.NoError(t, err)

	addr := listener.listener.Addr().String()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err, "Connection should be accepted even without PKI doc")

	time.Sleep(100 * time.Millisecond)

	listener.connsLock.RLock()
	connCount := len(listener.conns)
	listener.connsLock.RUnlock()
	require.Equal(t, 1, connCount, "Connection should be registered")

	conn.Close()
	listener.Shutdown()
}

func TestDecoyTrafficPreservedOnClientDisconnect(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap: make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replies:      make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:       make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:    new(sync.Mutex),
	}

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d.logbackend = logBackend
	d.log = logBackend.GetLogger("test")

	clientAppID := &[AppIDLength]byte{}
	copy(clientAppID[:], []byte("client-app-id-12"))

	clientSURBID := [sphinxConstants.SURBIDLength]byte{}
	daemonDecoySURBID := [sphinxConstants.SURBIDLength]byte{}
	copy(clientSURBID[:], []byte("client-surb-0001"))
	copy(daemonDecoySURBID[:], []byte("daemon-decoy-001"))

	d.replyLock.Lock()
	d.decoys[clientSURBID] = replyDescriptor{
		appID:   clientAppID,
		surbKey: []byte("client-surb-key"),
	}
	d.decoys[daemonDecoySURBID] = replyDescriptor{
		appID:   nil,
		surbKey: []byte("daemon-surb-key"),
	}
	d.replyLock.Unlock()

	d.replyLock.Lock()
	require.Len(t, d.decoys, 2)
	d.replyLock.Unlock()

	d.cleanupForAppID(clientAppID)

	d.replyLock.Lock()
	require.NotContains(t, d.decoys, clientSURBID)
	require.Contains(t, d.decoys, daemonDecoySURBID)
	require.Len(t, d.decoys, 1)
	d.replyLock.Unlock()
}

func TestReplyCleanupOnAppDisconnect(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap: make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replies:      make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:       make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:    new(sync.Mutex),
	}

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d.logbackend = logBackend
	d.log = logBackend.GetLogger("test")

	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("test-app-id-1234"))

	otherAppID := &[AppIDLength]byte{}
	copy(otherAppID[:], []byte("other-app-id-567"))

	testSURBID := [sphinxConstants.SURBIDLength]byte{}
	otherSURBID := [sphinxConstants.SURBIDLength]byte{}
	copy(testSURBID[:], []byte("test-reply-surb1"))
	copy(otherSURBID[:], []byte("other-reply-surb"))

	testMessageID := &[MessageIDLength]byte{}
	copy(testMessageID[:], []byte("test-message-id1"))

	d.replyLock.Lock()
	d.replies[testSURBID] = replyDescriptor{
		ID:      testMessageID,
		appID:   testAppID,
		surbKey: []byte("test-surb-key"),
	}
	d.replies[otherSURBID] = replyDescriptor{
		ID:      testMessageID,
		appID:   otherAppID,
		surbKey: []byte("other-surb-key"),
	}
	d.replyLock.Unlock()

	d.cleanupForAppID(testAppID)

	d.replyLock.Lock()
	require.NotContains(t, d.replies, testSURBID)
	require.Contains(t, d.replies, otherSURBID)
	d.replyLock.Unlock()
}

func TestNilAppIDEntriesPreserved(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap: make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replies:      make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:       make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:    new(sync.Mutex),
	}

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d.logbackend = logBackend
	d.log = logBackend.GetLogger("test")

	someAppID := &[AppIDLength]byte{}
	copy(someAppID[:], []byte("some-app-id-1234"))

	nilAppIDSURBID1 := [sphinxConstants.SURBIDLength]byte{}
	nilAppIDSURBID2 := [sphinxConstants.SURBIDLength]byte{}
	nilAppIDSURBID3 := [sphinxConstants.SURBIDLength]byte{}
	copy(nilAppIDSURBID1[:], []byte("nil-arq-surb-001"))
	copy(nilAppIDSURBID2[:], []byte("nil-reply-surb02"))
	copy(nilAppIDSURBID3[:], []byte("nil-decoy-surb03"))

	testQueryID := &[thin.QueryIDLength]byte{}
	copy(testQueryID[:], []byte("test-query-id1--"))
	testMessageID := &[MessageIDLength]byte{}
	copy(testMessageID[:], []byte("test-message-id1"))

	d.replyLock.Lock()
	d.arqSurbIDMap[nilAppIDSURBID1] = &ARQMessage{
		AppID:   nil,
		QueryID: testQueryID,
		SURBID:  &nilAppIDSURBID1,
	}
	d.replies[nilAppIDSURBID2] = replyDescriptor{
		ID:      testMessageID,
		appID:   nil,
		surbKey: []byte("nil-surb-key"),
	}
	d.decoys[nilAppIDSURBID3] = replyDescriptor{
		appID:   nil,
		surbKey: []byte("nil-decoy-key"),
	}
	d.replyLock.Unlock()

	d.cleanupForAppID(someAppID)

	d.replyLock.Lock()
	require.Contains(t, d.arqSurbIDMap, nilAppIDSURBID1, "ARQ with nil AppID should be preserved")
	require.Contains(t, d.replies, nilAppIDSURBID2, "Reply with nil AppID should be preserved")
	require.Contains(t, d.decoys, nilAppIDSURBID3, "Decoy with nil AppID should be preserved")
	d.replyLock.Unlock()
}
