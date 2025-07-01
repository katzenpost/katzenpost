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
	// Add some test channels to the channel map
	testChannelID1 := uint16(1001)
	testChannelID2 := uint16(1002)

	d.newChannelMapLock.Lock()
	d.newChannelMap[testChannelID1] = &ChannelDescriptor{
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		StoredEnvelopes:     make(map[[MessageIDLength]byte]*StoredEnvelopeData),
	}
	d.newChannelMap[testChannelID2] = &ChannelDescriptor{
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		StoredEnvelopes:     make(map[[MessageIDLength]byte]*StoredEnvelopeData),
	}
	d.newChannelMapLock.Unlock()

	// Add some SURB ID to channel mappings
	testSURBID1 := &[sphinxConstants.SURBIDLength]byte{}
	testSURBID2 := &[sphinxConstants.SURBIDLength]byte{}
	copy(testSURBID1[:], []byte("test-surb-id-001"))
	copy(testSURBID2[:], []byte("test-surb-id-002"))

	d.newSurbIDToChannelMapLock.Lock()
	d.newSurbIDToChannelMap[*testSURBID1] = testChannelID1
	d.newSurbIDToChannelMap[*testSURBID2] = testChannelID2
	d.newSurbIDToChannelMapLock.Unlock()

	// Add some channel replies for this App ID
	d.channelRepliesLock.Lock()
	d.channelReplies[*testSURBID1] = replyDescriptor{
		appID:   testAppID,
		surbKey: []byte("test-surb-key-1"),
	}
	d.channelReplies[*testSURBID2] = replyDescriptor{
		appID:   testAppID,
		surbKey: []byte("test-surb-key-2"),
	}
	d.channelRepliesLock.Unlock()

	// Verify that the channels and mappings exist before cleanup
	d.newChannelMapLock.RLock()
	require.Contains(t, d.newChannelMap, testChannelID1)
	require.Contains(t, d.newChannelMap, testChannelID2)
	d.newChannelMapLock.RUnlock()

	d.newSurbIDToChannelMapLock.RLock()
	require.Contains(t, d.newSurbIDToChannelMap, *testSURBID1)
	require.Contains(t, d.newSurbIDToChannelMap, *testSURBID2)
	d.newSurbIDToChannelMapLock.RUnlock()

	d.channelRepliesLock.RLock()
	require.Contains(t, d.channelReplies, *testSURBID1)
	require.Contains(t, d.channelReplies, *testSURBID2)
	d.channelRepliesLock.RUnlock()

	// Call the cleanup function
	d.cleanupChannelsForAppID(testAppID)

	// Verify that all channels and mappings for this App ID have been cleaned up
	d.newChannelMapLock.RLock()
	require.NotContains(t, d.newChannelMap, testChannelID1)
	require.NotContains(t, d.newChannelMap, testChannelID2)
	d.newChannelMapLock.RUnlock()

	d.newSurbIDToChannelMapLock.RLock()
	require.NotContains(t, d.newSurbIDToChannelMap, *testSURBID1)
	require.NotContains(t, d.newSurbIDToChannelMap, *testSURBID2)
	d.newSurbIDToChannelMapLock.RUnlock()

	d.channelRepliesLock.RLock()
	require.NotContains(t, d.channelReplies, *testSURBID1)
	require.NotContains(t, d.channelReplies, *testSURBID2)
	d.channelRepliesLock.RUnlock()

	t.Log("Channel cleanup test completed successfully")
}
