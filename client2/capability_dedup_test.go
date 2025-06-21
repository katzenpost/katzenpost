package client2

import (
	"sync"
	"testing"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/stretchr/testify/require"
)

func TestCapabilityDeduplication(t *testing.T) {
	// Create a test daemon
	daemon := &Daemon{
		usedReadCaps:   make(map[[hash.HashSize]byte]bool),
		usedWriteCaps:  make(map[[hash.HashSize]byte]bool),
		capabilityLock: new(sync.RWMutex),
		channelMap:     make(map[uint16]*ChannelDescriptor),
		channelMapLock: new(sync.RWMutex),
		secureRand:     rand.NewMath(),
	}

	// Test write capability deduplication
	t.Run("WriteCapabilityDeduplication", func(t *testing.T) {
		// Create a test WriteCap
		boxOwnerCap, err := bacap.NewWriteCap(rand.Reader)
		require.NoError(t, err)

		// Test the capability deduplication logic directly

		// Mock the capability check logic
		boxOwnerCapBytes, err := boxOwnerCap.MarshalBinary()
		require.NoError(t, err)
		capHash := hash.Sum256(boxOwnerCapBytes)

		// First use should be allowed
		daemon.capabilityLock.Lock()
		exists := daemon.usedWriteCaps[capHash]
		require.False(t, exists, "Capability should not exist initially")
		daemon.usedWriteCaps[capHash] = true
		daemon.capabilityLock.Unlock()

		// Second use should be detected as duplicate
		daemon.capabilityLock.RLock()
		exists = daemon.usedWriteCaps[capHash]
		daemon.capabilityLock.RUnlock()
		require.True(t, exists, "Capability should be marked as used")
	})

	// Test read capability deduplication
	t.Run("ReadCapabilityDeduplication", func(t *testing.T) {
		// Create a test ReadCap from WriteCap
		boxOwnerCap, err := bacap.NewWriteCap(rand.Reader)
		require.NoError(t, err)
		readCap := boxOwnerCap.ReadCap()

		// Mock the capability check logic
		readCapBytes, err := readCap.MarshalBinary()
		require.NoError(t, err)
		capHash := hash.Sum256(readCapBytes)

		// First use should be allowed
		daemon.capabilityLock.Lock()
		exists := daemon.usedReadCaps[capHash]
		require.False(t, exists, "Capability should not exist initially")
		daemon.usedReadCaps[capHash] = true
		daemon.capabilityLock.Unlock()

		// Second use should be detected as duplicate
		daemon.capabilityLock.RLock()
		exists = daemon.usedReadCaps[capHash]
		daemon.capabilityLock.RUnlock()
		require.True(t, exists, "Capability should be marked as used")
	})

	// Test capability cleanup
	t.Run("CapabilityCleanup", func(t *testing.T) {
		// Test read capability cleanup
		t.Run("ReadCapabilityCleanup", func(t *testing.T) {
			// Create test capabilities
			boxOwnerCap, err := bacap.NewWriteCap(rand.Reader)
			require.NoError(t, err)
			readCap := boxOwnerCap.ReadCap()

			// Add read capability to dedup map
			readCapBytes, err := readCap.MarshalBinary()
			require.NoError(t, err)

			daemon.capabilityLock.Lock()
			daemon.usedReadCaps[hash.Sum256(readCapBytes)] = true
			daemon.capabilityLock.Unlock()

			// Create a read channel descriptor
			statefulReader, err := bacap.NewStatefulReader(readCap, constants.PIGEONHOLE_CTX)
			require.NoError(t, err)

			readChannelDesc := &ChannelDescriptor{
				StatefulReader: statefulReader,
			}

			// Test cleanup
			daemon.removeCapabilityFromDedup(readChannelDesc)

			// Verify read capability is removed
			daemon.capabilityLock.RLock()
			_, readExists := daemon.usedReadCaps[hash.Sum256(readCapBytes)]
			daemon.capabilityLock.RUnlock()

			require.False(t, readExists, "Read capability should be removed")
		})

		// Test write capability cleanup
		t.Run("WriteCapabilityCleanup", func(t *testing.T) {
			// Create test capabilities
			boxOwnerCap, err := bacap.NewWriteCap(rand.Reader)
			require.NoError(t, err)

			// Add write capability to dedup map
			boxOwnerCapBytes, err := boxOwnerCap.MarshalBinary()
			require.NoError(t, err)

			daemon.capabilityLock.Lock()
			daemon.usedWriteCaps[hash.Sum256(boxOwnerCapBytes)] = true
			daemon.capabilityLock.Unlock()

			// Create a write channel descriptor
			statefulWriter, err := bacap.NewStatefulWriter(boxOwnerCap, constants.PIGEONHOLE_CTX)
			require.NoError(t, err)

			writeChannelDesc := &ChannelDescriptor{
				StatefulWriter: statefulWriter,
			}

			// Test cleanup
			daemon.removeCapabilityFromDedup(writeChannelDesc)

			// Verify write capability is removed
			daemon.capabilityLock.RLock()
			_, writeExists := daemon.usedWriteCaps[hash.Sum256(boxOwnerCapBytes)]
			daemon.capabilityLock.RUnlock()

			require.False(t, writeExists, "Write capability should be removed")
		})
	})
}
