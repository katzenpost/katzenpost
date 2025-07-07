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

func TestDaemonUniqueChannels

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
		StoredEnvelopes:     make(map[[MessageIDLength]byte]*StoredEnvelopeData),
	}
	d.newChannelMap[testChannelID2] = &ChannelDescriptor{
		AppID:               testAppID,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		StoredEnvelopes:     make(map[[MessageIDLength]byte]*StoredEnvelopeData),
	}
	d.newChannelMap[otherChannelID] = &ChannelDescriptor{
		AppID:               otherAppID,
		EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		StoredEnvelopes:     make(map[[MessageIDLength]byte]*StoredEnvelopeData),
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
