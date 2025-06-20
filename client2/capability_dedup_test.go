package client2

import (
	"sync"
	"testing"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/stretchr/testify/require"
)

func TestCapabilityDeduplication(t *testing.T) {
	// Create a test daemon
	daemon := &Daemon{
		usedReadCaps:   make(map[string]bool),
		usedWriteCaps:  make(map[string]bool),
		capabilityLock: new(sync.RWMutex),
		channelMap:     make(map[[thin.ChannelIDLength]byte]*ChannelDescriptor),
		channelMapLock: new(sync.RWMutex),
		secureRand:     rand.NewMath(),
	}

	// Test write capability deduplication
	t.Run("WriteCapabilityDeduplication", func(t *testing.T) {
		// Create a test BoxOwnerCap
		boxOwnerCap, err := bacap.NewBoxOwnerCap(rand.Reader)
		require.NoError(t, err)

		// Test the capability deduplication logic directly

		// Mock the capability check logic
		boxOwnerCapBytes, err := boxOwnerCap.MarshalBinary()
		require.NoError(t, err)
		capKey := string(boxOwnerCapBytes)

		// First use should be allowed
		daemon.capabilityLock.Lock()
		exists := daemon.usedWriteCaps[capKey]
		require.False(t, exists, "Capability should not exist initially")
		daemon.usedWriteCaps[capKey] = true
		daemon.capabilityLock.Unlock()

		// Second use should be detected as duplicate
		daemon.capabilityLock.RLock()
		exists = daemon.usedWriteCaps[capKey]
		daemon.capabilityLock.RUnlock()
		require.True(t, exists, "Capability should be marked as used")
	})

	// Test read capability deduplication
	t.Run("ReadCapabilityDeduplication", func(t *testing.T) {
		// Create a test UniversalReadCap from BoxOwnerCap
		boxOwnerCap, err := bacap.NewBoxOwnerCap(rand.Reader)
		require.NoError(t, err)
		readCap := boxOwnerCap.UniversalReadCap()

		// Mock the capability check logic
		readCapBytes, err := readCap.MarshalBinary()
		require.NoError(t, err)
		capKey := string(readCapBytes)

		// First use should be allowed
		daemon.capabilityLock.Lock()
		exists := daemon.usedReadCaps[capKey]
		require.False(t, exists, "Capability should not exist initially")
		daemon.usedReadCaps[capKey] = true
		daemon.capabilityLock.Unlock()

		// Second use should be detected as duplicate
		daemon.capabilityLock.RLock()
		exists = daemon.usedReadCaps[capKey]
		daemon.capabilityLock.RUnlock()
		require.True(t, exists, "Capability should be marked as used")
	})

	// Test capability cleanup
	t.Run("CapabilityCleanup", func(t *testing.T) {
		// Create test capabilities
		boxOwnerCap, err := bacap.NewBoxOwnerCap(rand.Reader)
		require.NoError(t, err)
		readCap := boxOwnerCap.UniversalReadCap()

		// Add capabilities to dedup maps
		boxOwnerCapBytes, err := boxOwnerCap.MarshalBinary()
		require.NoError(t, err)
		readCapBytes, err := readCap.MarshalBinary()
		require.NoError(t, err)

		daemon.capabilityLock.Lock()
		daemon.usedWriteCaps[string(boxOwnerCapBytes)] = true
		daemon.usedReadCaps[string(readCapBytes)] = true
		daemon.capabilityLock.Unlock()

		// Create a channel descriptor with both capabilities
		statefulReader, err := bacap.NewStatefulReader(readCap, constants.PIGEONHOLE_CTX)
		require.NoError(t, err)

		channelDesc := &ChannelDescriptor{
			BoxOwnerCap:    boxOwnerCap,
			StatefulReader: statefulReader,
		}

		// Test cleanup
		daemon.removeCapabilityFromDedup(channelDesc)

		// Verify capabilities are removed
		daemon.capabilityLock.RLock()
		_, writeExists := daemon.usedWriteCaps[string(boxOwnerCapBytes)]
		_, readExists := daemon.usedReadCaps[string(readCapBytes)]
		daemon.capabilityLock.RUnlock()

		require.False(t, writeExists, "Write capability should be removed")
		require.False(t, readExists, "Read capability should be removed")
	})
}
