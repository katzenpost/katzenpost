// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"

	dirauthconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/replica/common"
)

const (
	// Test envelope hash used across multiple test functions
	testEnvelopeHashString = "test-envelope-hash-12345678901234567890123456789012"

	// Test assertion message for courier reply parsing
	errShouldParseReply = "Should be able to parse courier reply"

	// Error message for unimplemented mock methods
	errNotImplemented = "not implemented"
)

// TestCourierCacheBasicOperations tests basic cache operations
func TestCourierCacheBasicOperations(t *testing.T) {
	// Create a courier with empty cache
	courier := createTestCourier(t)

	// Test initial state - cache should be empty
	require.Equal(t, 0, len(courier.dedupCache))

	// Create test envelope hash
	envHash := [hash.HashSize]byte{}
	copy(envHash[:], []byte(testEnvelopeHashString))

	// Create test replica reply
	reply := &commands.ReplicaMessageReply{
		EnvelopeHash:  &envHash,
		ReplicaID:     0,
		ErrorCode:     0,
		EnvelopeReply: []byte("test-reply-payload"),
		IsRead:        true, // Set IsRead to true so it will be cached
	}

	// Test CacheReply - first reply
	courier.CacheReply(reply)

	// Verify cache entry was created
	require.Equal(t, 1, len(courier.dedupCache))

	courier.dedupCacheLock.RLock()
	entry, exists := courier.dedupCache[envHash]
	courier.dedupCacheLock.RUnlock()

	require.True(t, exists)
	require.NotNil(t, entry)
	require.Equal(t, reply, entry.EnvelopeReplies[0])
	require.Nil(t, entry.EnvelopeReplies[1])
}

// TestCourierCacheDualReplies tests caching replies from both replicas
func TestCourierCacheDualReplies(t *testing.T) {
	courier := createTestCourier(t)

	envHash := [hash.HashSize]byte{}
	copy(envHash[:], []byte(testEnvelopeHashString))

	// Create first replica reply
	reply1 := &commands.ReplicaMessageReply{
		EnvelopeHash:  &envHash,
		ReplicaID:     0,
		ErrorCode:     0,
		EnvelopeReply: []byte("reply-from-replica-0"),
		IsRead:        true, // Set IsRead to true so it will be cached
	}

	// Create second replica reply
	reply2 := &commands.ReplicaMessageReply{
		EnvelopeHash:  &envHash,
		ReplicaID:     1,
		ErrorCode:     0,
		EnvelopeReply: []byte("reply-from-replica-1"),
		IsRead:        true, // Set IsRead to true so it will be cached
	}

	// Cache first reply
	courier.CacheReply(reply1)

	// Verify first reply is cached
	courier.dedupCacheLock.RLock()
	entry, exists := courier.dedupCache[envHash]
	courier.dedupCacheLock.RUnlock()

	require.True(t, exists)
	require.Equal(t, reply1, entry.EnvelopeReplies[0])
	require.Nil(t, entry.EnvelopeReplies[1])

	// Cache second reply
	courier.CacheReply(reply2)

	// Verify both replies are cached
	courier.dedupCacheLock.RLock()
	entry = courier.dedupCache[envHash]
	courier.dedupCacheLock.RUnlock()

	require.Equal(t, reply1, entry.EnvelopeReplies[0])
	require.Equal(t, reply2, entry.EnvelopeReplies[1])
}

// TestCourierCacheOverflow tests behavior when trying to cache more than 2 replies
func TestCourierCacheOverflow(t *testing.T) {
	courier := createTestCourier(t)

	envHash := [hash.HashSize]byte{}
	copy(envHash[:], []byte(testEnvelopeHashString))

	// Create three replica replies
	reply1 := &commands.ReplicaMessageReply{
		EnvelopeHash:  &envHash,
		ReplicaID:     0,
		ErrorCode:     0,
		EnvelopeReply: []byte("reply-1"),
		IsRead:        true, // Add this flag to ensure replies are cached
	}

	reply2 := &commands.ReplicaMessageReply{
		EnvelopeHash:  &envHash,
		ReplicaID:     1,
		ErrorCode:     0,
		EnvelopeReply: []byte("reply-2"),
		IsRead:        true, // Add this flag to ensure replies are cached
	}

	reply3 := &commands.ReplicaMessageReply{
		EnvelopeHash:  &envHash,
		ReplicaID:     0,
		ErrorCode:     0,
		EnvelopeReply: []byte("reply-3-should-be-ignored"),
		IsRead:        true, // Add this flag to ensure replies are cached
	}

	// Cache all three replies
	courier.CacheReply(reply1)
	courier.CacheReply(reply2)
	courier.CacheReply(reply3) // This should be ignored

	// Verify only first two replies are cached
	courier.dedupCacheLock.RLock()
	entry := courier.dedupCache[envHash]
	courier.dedupCacheLock.RUnlock()

	require.Equal(t, reply1, entry.EnvelopeReplies[0])
	require.Equal(t, reply2, entry.EnvelopeReplies[1])
	require.NotEqual(t, reply3.EnvelopeReply, entry.EnvelopeReplies[0].EnvelopeReply)
}

// TestCourierCacheHandleOldMessage tests retrieving cached replies
func TestCourierCacheHandleOldMessage(t *testing.T) {
	courier := createTestCourier(t)

	envHash := [hash.HashSize]byte{}
	copy(envHash[:], []byte(testEnvelopeHashString))

	// Create test replies
	reply1 := &commands.ReplicaMessageReply{
		EnvelopeHash:  &envHash,
		ReplicaID:     0,
		ErrorCode:     0,
		EnvelopeReply: []byte("cached-reply-0"),
		IsRead:        true, // Add this flag to ensure replies are cached
	}

	reply2 := &commands.ReplicaMessageReply{
		EnvelopeHash:  &envHash,
		ReplicaID:     1,
		ErrorCode:     0,
		EnvelopeReply: []byte("cached-reply-1"),
		IsRead:        true, // Add this flag to ensure replies are cached
	}

	// Cache both replies
	courier.CacheReply(reply1)
	courier.CacheReply(reply2)

	// Create courier envelope requesting reply index 0
	courierEnv := &common.CourierEnvelope{
		ReplyIndex: 0,
	}

	// Get cached entry
	courier.dedupCacheLock.RLock()
	cacheEntry := courier.dedupCache[envHash]
	courier.dedupCacheLock.RUnlock()

	// Test handleOldMessage for reply index 0
	replyBytes := courier.handleOldMessage(cacheEntry, &envHash, courierEnv)

	// Parse the reply
	courierReply, err := common.CourierEnvelopeReplyFromBytes(replyBytes)
	require.NoError(t, err, errShouldParseReply)

	require.Equal(t, uint8(0), courierReply.ReplyIndex)
	require.Equal(t, reply1.EnvelopeReply, courierReply.Payload)

	// Test handleOldMessage for reply index 1
	courierEnv.ReplyIndex = 1
	replyBytes = courier.handleOldMessage(cacheEntry, &envHash, courierEnv)

	courierReply, err = common.CourierEnvelopeReplyFromBytes(replyBytes)
	require.NoError(t, err, errShouldParseReply)

	require.Equal(t, uint8(1), courierReply.ReplyIndex)
	require.Equal(t, reply2.EnvelopeReply, courierReply.Payload)
}

// TestCourierCacheFallbackBehavior tests fallback when requested reply index is not available
func TestCourierCacheFallbackBehavior(t *testing.T) {
	courier := createTestCourier(t)

	envHash := [hash.HashSize]byte{}
	copy(envHash[:], []byte(testEnvelopeHashString))

	// Cache only reply from replica 1 (index 1)
	reply1 := &commands.ReplicaMessageReply{
		EnvelopeHash:  &envHash,
		ReplicaID:     1,
		ErrorCode:     0,
		EnvelopeReply: []byte("only-reply-from-replica-1"),
	}

	courier.CacheReply(reply1)

	// Manually set up cache entry with reply only in slot 1
	courier.dedupCacheLock.Lock()
	courier.dedupCache[envHash] = &CourierBookKeeping{
		Epoch: 1,
		EnvelopeReplies: [2]*commands.ReplicaMessageReply{
			nil,    // No reply in slot 0
			reply1, // Reply in slot 1
		},
	}
	courier.dedupCacheLock.Unlock()

	// Request reply index 0 (which doesn't exist)
	courierEnv := &common.CourierEnvelope{
		ReplyIndex: 0,
	}

	courier.dedupCacheLock.RLock()
	cacheEntry := courier.dedupCache[envHash]
	courier.dedupCacheLock.RUnlock()

	replyBytes := courier.handleOldMessage(cacheEntry, &envHash, courierEnv)

	courierReply, err := common.CourierEnvelopeReplyFromBytes(replyBytes)
	require.NoError(t, err, errShouldParseReply)

	// Should fallback to reply index 1 and update the reply index
	require.Equal(t, uint8(1), courierReply.ReplyIndex)
	require.Equal(t, reply1.EnvelopeReply, courierReply.Payload)
}

// TestCourierCacheEmptyResponse tests behavior when no replies are cached
func TestCourierCacheEmptyResponse(t *testing.T) {
	courier := createTestCourier(t)

	envHash := [hash.HashSize]byte{}
	copy(envHash[:], []byte(testEnvelopeHashString))

	// Create cache entry with no replies
	cacheEntry := &CourierBookKeeping{
		Epoch:           1,
		EnvelopeReplies: [2]*commands.ReplicaMessageReply{nil, nil},
	}

	courierEnv := &common.CourierEnvelope{
		ReplyIndex: 0,
	}

	replyBytes := courier.handleOldMessage(cacheEntry, &envHash, courierEnv)

	courierReply, err := common.CourierEnvelopeReplyFromBytes(replyBytes)
	require.NoError(t, err, errShouldParseReply)

	require.Equal(t, uint8(0), courierReply.ReplyIndex)
	require.Empty(t, courierReply.Payload)
	require.Equal(t, uint8(0), courierReply.ErrorCode)
}

// Helper function to create a test courier
func createTestCourier(t *testing.T) *Courier {
	// Create minimal test configuration
	sphinxNikeSchemeName := "X25519"
	geo := &geo.Geometry{
		PacketLength:                3082,
		HeaderLength:                476,
		RoutingInfoLength:           410,
		PerHopRoutingInfoLength:     82,
		SURBLength:                  572,
		SphinxPlaintextHeaderLength: 2,
		PayloadTagLength:            32,
		ForwardPayloadLength:        2574,
		UserForwardPayloadLength:    2000,
		NextNodeHopLength:           65,
		SPRPKeyMaterialLength:       64,
		NIKEName:                    sphinxNikeSchemeName,
	}

	replicaSchemeName := "CTIDH1024-X25519"
	replicaScheme := schemes.ByName(replicaSchemeName)
	require.NotNil(t, replicaScheme)

	cmds := commands.NewStorageReplicaCommands(geo, replicaScheme)

	// Create mock PKI for testing
	mockPKI := &mockPKIClient{
		doc: &pki.Document{
			Epoch: 1,
		},
	}

	// Create mock server with minimal configuration
	backendLog, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	server := &Server{
		cfg: &config.Config{
			SphinxGeometry: geo,
			WireKEMScheme:  "Xwing",
			PKIScheme:      "ed25519",
			EnvelopeScheme: replicaSchemeName,
			PKI: &config.PKI{
				Voting: &config.Voting{
					Authorities: []*dirauthconfig.Authority{
						&dirauthconfig.Authority{},
					},
				},
			},
		},
		logBackend: backendLog,
	}

	server.log = server.logBackend.GetLogger("courier-server")
	server.PKI, err = newPKIWorker(server, mockPKI, server.logBackend.GetLogger("courier-pkiworker"))
	require.NoError(t, err)

	courier := NewCourier(server, cmds, replicaScheme)
	require.NotNil(t, courier)
	require.NotNil(t, courier.dedupCache)

	return courier
}

// TestCourierCacheConcurrentAccess tests thread safety of cache operations
func TestCourierCacheConcurrentAccess(t *testing.T) {
	courier := createTestCourier(t)

	envHash := [hash.HashSize]byte{}
	copy(envHash[:], []byte(testEnvelopeHashString))

	// Create multiple replies
	replies := make([]*commands.ReplicaMessageReply, 10)
	for i := 0; i < 10; i++ {
		replies[i] = &commands.ReplicaMessageReply{
			EnvelopeHash:  &envHash,
			ReplicaID:     uint8(i % 2), // Alternate between replica 0 and 1
			ErrorCode:     0,
			EnvelopeReply: []byte("concurrent-reply"),
			IsRead:        true, // Add this flag to ensure replies are cached
		}
	}

	// Concurrently cache replies
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(reply *commands.ReplicaMessageReply) {
			courier.CacheReply(reply)
			done <- true
		}(replies[i])
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify cache state is consistent
	courier.dedupCacheLock.RLock()
	entry, exists := courier.dedupCache[envHash]
	courier.dedupCacheLock.RUnlock()

	require.True(t, exists)
	require.NotNil(t, entry)

	// Should have at most 2 replies (one per replica)
	replyCount := 0
	if entry.EnvelopeReplies[0] != nil {
		replyCount++
	}
	if entry.EnvelopeReplies[1] != nil {
		replyCount++
	}
	require.LessOrEqual(t, replyCount, 2)
}

// TestCourierCacheMultipleEnvelopes tests caching for different envelope hashes
func TestCourierCacheMultipleEnvelopes(t *testing.T) {
	courier := createTestCourier(t)

	// Create multiple envelope hashes
	envHashes := make([][hash.HashSize]byte, 5)
	for i := 0; i < 5; i++ {
		copy(envHashes[i][:], []byte("test-envelope-hash-"+string(rune('A'+i))+"234567890123456789012345678901"))
	}

	// Cache replies for each envelope
	for i, envHash := range envHashes {
		reply := &commands.ReplicaMessageReply{
			EnvelopeHash:  &envHash,
			ReplicaID:     uint8(i % 2),
			ErrorCode:     0,
			EnvelopeReply: []byte("reply-for-envelope-" + string(rune('A'+i))),
			IsRead:        true, // Add this flag to ensure replies are cached
		}
		courier.CacheReply(reply)
	}

	// Verify all envelopes are cached separately
	require.Equal(t, 5, len(courier.dedupCache))

	for i, envHash := range envHashes {
		courier.dedupCacheLock.RLock()
		entry, exists := courier.dedupCache[envHash]
		courier.dedupCacheLock.RUnlock()

		require.True(t, exists)
		require.NotNil(t, entry)

		expectedReply := []byte("reply-for-envelope-" + string(rune('A'+i)))

		// CacheReply stores replies sequentially in slot 0 first, regardless of ReplicaID
		// Since each envelope hash gets only one reply, it should be in slot 0
		require.NotNil(t, entry.EnvelopeReplies[0])
		require.Equal(t, expectedReply, entry.EnvelopeReplies[0].EnvelopeReply)
		require.Equal(t, uint8(i%2), entry.EnvelopeReplies[0].ReplicaID)

		// Second slot should be nil since we only cached one reply per envelope
		require.Nil(t, entry.EnvelopeReplies[1])
	}
}

// TestCourierCacheEpochTracking tests that cache entries track epochs correctly
func TestCourierCacheEpochTracking(t *testing.T) {
	courier := createTestCourier(t)

	// Get the current epoch for testing
	currentEpoch, _, _ := epochtime.Now()
	testEpoch := currentEpoch

	mockPKI := &mockPKIClient{
		doc: &pki.Document{
			Epoch: testEpoch,
		},
	}

	// Replace the PKI worker with one that has our test epoch
	var err error
	courier.server.PKI, err = newPKIWorker(courier.server, mockPKI, courier.server.logBackend.GetLogger("courier-pkiworker"))
	require.NoError(t, err)

	// Manually populate the PKI worker's cache with the test document for the current epoch
	courier.server.PKI.lock.Lock()
	courier.server.PKI.docs[testEpoch] = mockPKI.doc
	courier.server.PKI.lock.Unlock()

	envHash := [hash.HashSize]byte{}
	copy(envHash[:], []byte(testEnvelopeHashString))

	reply := &commands.ReplicaMessageReply{
		EnvelopeHash:  &envHash,
		ReplicaID:     0,
		ErrorCode:     0,
		EnvelopeReply: []byte("test-reply"),
		IsRead:        true, // Add this flag to ensure the reply is cached
	}

	courier.CacheReply(reply)

	// Verify epoch is tracked correctly
	courier.dedupCacheLock.RLock()
	entry := courier.dedupCache[envHash]
	courier.dedupCacheLock.RUnlock()

	require.Equal(t, testEpoch, entry.Epoch)
}

// TestCourierCacheErrorReplies tests caching of error replies
func TestCourierCacheErrorReplies(t *testing.T) {
	courier := createTestCourier(t)

	envHash := [hash.HashSize]byte{}
	copy(envHash[:], []byte(testEnvelopeHashString))

	// Create error reply
	errorReply := &commands.ReplicaMessageReply{
		EnvelopeHash:  &envHash,
		ReplicaID:     0,
		ErrorCode:     1, // Error code
		EnvelopeReply: []byte("error-occurred"),
		IsRead:        true, // Add this flag to ensure the reply is cached
	}

	courier.CacheReply(errorReply)

	// Verify error reply is cached
	courier.dedupCacheLock.RLock()
	entry := courier.dedupCache[envHash]
	courier.dedupCacheLock.RUnlock()

	require.Equal(t, errorReply, entry.EnvelopeReplies[0])
	require.Equal(t, uint8(1), entry.EnvelopeReplies[0].ErrorCode)
}

// TestCourierCacheNilEnvelopeHash tests behavior with nil envelope hash
func TestCourierCacheNilEnvelopeHash(t *testing.T) {
	courier := createTestCourier(t)

	// Create reply with nil envelope hash - this should not panic
	reply := &commands.ReplicaMessageReply{
		EnvelopeHash:  nil,
		ReplicaID:     0,
		ErrorCode:     0,
		EnvelopeReply: []byte("test-reply"),
	}

	// This should not panic but also should not cache anything
	require.NotPanics(t, func() {
		courier.CacheReply(reply)
	}, "CacheReply should not panic with nil envelope hash")

	// Cache should remain empty
	require.Equal(t, 0, len(courier.dedupCache))
}

type mockPKIClient struct {
	doc *pki.Document
}

// Get returns the PKI document along with the raw serialized form for the provided epoch.
func (m *mockPKIClient) Get(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	blob, err := m.doc.MarshalCertificate()
	if err != nil {
		return nil, nil, err
	}
	return m.doc, blob, nil
}

// Post posts the node's descriptor to the PKI for the provided epoch.
func (m *mockPKIClient) Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.MixDescriptor, loopstats *loops.LoopStats) error {
	panic(errNotImplemented)
}

// PostReplica posts the pigeonhole storage replica node's descriptor to the PKI for the provided epoch.
func (m *mockPKIClient) PostReplica(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.ReplicaDescriptor) error {
	panic(errNotImplemented)
}

// Deserialize returns PKI document given the raw bytes.
func (m *mockPKIClient) Deserialize(raw []byte) (*pki.Document, error) {
	panic(errNotImplemented)
}
