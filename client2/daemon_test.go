//go:build !windows
// +build !windows

package client2

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
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

func TestChannelCleanupOnAppDisconnect(t *testing.T) {
	// Create a minimal daemon instance for testing
	d := &Daemon{
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
	}

	// Create a simple logger for testing
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d.logbackend = logBackend
	d.log = logBackend.GetLogger("test")

	// Create a test App ID
	testAppID := &[AppIDLength]byte{}
	copy(testAppID[:], []byte("test-app-id-1234"))

	// Simulate creating some channels for this App ID by adding entries to the maps
	// Create a second App ID for testing that other apps aren't affected
	otherAppID := &[AppIDLength]byte{}
	copy(otherAppID[:], []byte("other-app-id-567"))

	// Add some test channels to the channel map
	testChannelID1 := uint16(1001)
	testChannelID2 := uint16(1002)
	otherChannelID := uint16(1003) // Channel belonging to different App ID

	d.newChannelMapLock.Lock()
	d.newChannelMap[testChannelID1] = &ChannelDescriptor{
		AppID:               testAppID,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
	}
	d.newChannelMap[testChannelID2] = &ChannelDescriptor{
		AppID:               testAppID,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
	}
	d.newChannelMap[otherChannelID] = &ChannelDescriptor{
		AppID:               otherAppID,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
	}
	d.newChannelMapLock.Unlock()

	// Add some SURB ID to channel mappings
	testSURBID1 := &[sphinxConstants.SURBIDLength]byte{}
	testSURBID2 := &[sphinxConstants.SURBIDLength]byte{}
	otherSURBID := &[sphinxConstants.SURBIDLength]byte{}
	copy(testSURBID1[:], []byte("test-surb-id-001"))
	copy(testSURBID2[:], []byte("test-surb-id-002"))
	copy(otherSURBID[:], []byte("other-surb-id-01"))

	d.newSurbIDToChannelMapLock.Lock()
	d.newSurbIDToChannelMap[*testSURBID1] = testChannelID1
	d.newSurbIDToChannelMap[*testSURBID2] = testChannelID2
	d.newSurbIDToChannelMap[*otherSURBID] = otherChannelID
	d.newSurbIDToChannelMapLock.Unlock()

	// Add some channel replies for both App IDs
	d.channelRepliesLock.Lock()
	d.channelReplies[*testSURBID1] = replyDescriptor{
		appID:   testAppID,
		surbKey: []byte("test-surb-key-1"),
	}
	d.channelReplies[*testSURBID2] = replyDescriptor{
		appID:   testAppID,
		surbKey: []byte("test-surb-key-2"),
	}
	d.channelReplies[*otherSURBID] = replyDescriptor{
		appID:   otherAppID,
		surbKey: []byte("other-surb-key-1"),
	}
	d.channelRepliesLock.Unlock()

	// Verify that the channels and mappings exist before cleanup
	d.newChannelMapLock.RLock()
	require.Contains(t, d.newChannelMap, testChannelID1)
	require.Contains(t, d.newChannelMap, testChannelID2)
	require.Contains(t, d.newChannelMap, otherChannelID)
	d.newChannelMapLock.RUnlock()

	d.newSurbIDToChannelMapLock.RLock()
	require.Contains(t, d.newSurbIDToChannelMap, *testSURBID1)
	require.Contains(t, d.newSurbIDToChannelMap, *testSURBID2)
	require.Contains(t, d.newSurbIDToChannelMap, *otherSURBID)
	d.newSurbIDToChannelMapLock.RUnlock()

	d.channelRepliesLock.RLock()
	require.Contains(t, d.channelReplies, *testSURBID1)
	require.Contains(t, d.channelReplies, *testSURBID2)
	require.Contains(t, d.channelReplies, *otherSURBID)
	d.channelRepliesLock.RUnlock()

	// Call the cleanup function
	d.cleanupChannelsForAppID(testAppID)

	// Verify that all channels and mappings for the target App ID have been cleaned up
	d.newChannelMapLock.RLock()
	require.NotContains(t, d.newChannelMap, testChannelID1)
	require.NotContains(t, d.newChannelMap, testChannelID2)
	// But the other App ID's channel should still exist
	require.Contains(t, d.newChannelMap, otherChannelID)
	d.newChannelMapLock.RUnlock()

	d.newSurbIDToChannelMapLock.RLock()
	require.NotContains(t, d.newSurbIDToChannelMap, *testSURBID1)
	require.NotContains(t, d.newSurbIDToChannelMap, *testSURBID2)
	// But the other App ID's SURB mapping should still exist
	require.Contains(t, d.newSurbIDToChannelMap, *otherSURBID)
	d.newSurbIDToChannelMapLock.RUnlock()

	d.channelRepliesLock.RLock()
	require.NotContains(t, d.channelReplies, *testSURBID1)
	require.NotContains(t, d.channelReplies, *testSURBID2)
	// But the other App ID's channel reply should still exist
	require.Contains(t, d.channelReplies, *otherSURBID)
	d.channelRepliesLock.RUnlock()

	t.Log("Channel cleanup test completed successfully - target App ID cleaned up, other App ID preserved")
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
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replies:                   make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:                    make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:                 new(sync.Mutex),
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newChannelMapXXX:          make(map[uint16]bool),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
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

	d.cleanupChannelsForAppID(clientAppID)

	d.replyLock.Lock()
	require.NotContains(t, d.decoys, clientSURBID)
	require.Contains(t, d.decoys, daemonDecoySURBID)
	require.Len(t, d.decoys, 1)
	d.replyLock.Unlock()

	t.Log("Decoy traffic preservation test completed successfully - daemon decoys preserved")
}

func TestReplyCleanupOnAppDisconnect(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replies:                   make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:                    make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:                 new(sync.Mutex),
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newChannelMapXXX:          make(map[uint16]bool),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
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

	d.cleanupChannelsForAppID(testAppID)

	d.replyLock.Lock()
	require.NotContains(t, d.replies, testSURBID)
	require.Contains(t, d.replies, otherSURBID)
	d.replyLock.Unlock()

	t.Log("Reply cleanup test completed successfully")
}

func TestNilAppIDEntriesPreserved(t *testing.T) {
	d := &Daemon{
		arqSurbIDMap:              make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replies:                   make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:                    make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:                 new(sync.Mutex),
		newChannelMap:             make(map[uint16]*ChannelDescriptor),
		newChannelMapLock:         new(sync.RWMutex),
		newChannelMapXXX:          make(map[uint16]bool),
		newSurbIDToChannelMap:     make(map[[sphinxConstants.SURBIDLength]byte]uint16),
		newSurbIDToChannelMapLock: new(sync.RWMutex),
		channelReplies:            make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		channelRepliesLock:        new(sync.RWMutex),
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

	d.cleanupChannelsForAppID(someAppID)

	d.replyLock.Lock()
	require.Contains(t, d.arqSurbIDMap, nilAppIDSURBID1, "ARQ with nil AppID should be preserved")
	require.Contains(t, d.replies, nilAppIDSURBID2, "Reply with nil AppID should be preserved")
	require.Contains(t, d.decoys, nilAppIDSURBID3, "Decoy with nil AppID should be preserved")
	d.replyLock.Unlock()

	t.Log("Nil AppID entries preservation test completed successfully")
}
