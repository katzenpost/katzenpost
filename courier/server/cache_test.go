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
	"github.com/katzenpost/katzenpost/pigeonhole"
)

const (
	// Test envelope hash used across multiple test functions
	testEnvelopeHashString = "test-envelope-hash-12345678901234567890123456789012"

	// Test assertion message for courier reply parsing
	errShouldParseReply = "Should be able to parse courier reply"

	// Error message for unimplemented mock methods
	errNotImplemented = "not implemented"
)

// Test helper functions to eliminate code duplication

// createTestEnvelopeHash creates a test envelope hash from the standard test string
func createTestEnvelopeHash() [hash.HashSize]byte {
	var envHash [hash.HashSize]byte
	copy(envHash[:], []byte(testEnvelopeHashString))
	return envHash
}

// createTestEnvelopeHashWithSuffix creates a test envelope hash with a custom suffix
func createTestEnvelopeHashWithSuffix(suffix string) [hash.HashSize]byte {
	var envHash [hash.HashSize]byte
	hashString := "test-envelope-hash-" + suffix + "234567890123456789012345678901"
	copy(envHash[:], []byte(hashString))
	return envHash
}

// createTestReply creates a standard test reply with the given parameters
func createTestReply(envHash *[hash.HashSize]byte, replicaID uint8, payload string, isRead bool) *commands.ReplicaMessageReply {
	return &commands.ReplicaMessageReply{
		EnvelopeHash:  envHash,
		ReplicaID:     replicaID,
		ErrorCode:     0,
		EnvelopeReply: []byte(payload),
		IsRead:        isRead,
	}
}

// createTestErrorReply creates a test reply with an error code
func createTestErrorReply(envHash *[hash.HashSize]byte, replicaID uint8, errorCode uint8, payload string, isRead bool) *commands.ReplicaMessageReply {
	return &commands.ReplicaMessageReply{
		EnvelopeHash:  envHash,
		ReplicaID:     replicaID,
		ErrorCode:     errorCode,
		EnvelopeReply: []byte(payload),
		IsRead:        isRead,
	}
}

// setupCacheEntry sets up a cache entry with both replica IDs
func setupCacheEntry(courier *Courier, envHash [hash.HashSize]byte, epoch uint64) {
	courier.dedupCacheLock.Lock()
	courier.dedupCache[envHash] = &CourierBookKeeping{
		Epoch:                epoch,
		IntermediateReplicas: [2]uint8{0, 1}, // Both replicas are expected
		EnvelopeReplies:      [2]*commands.ReplicaMessageReply{nil, nil},
	}
	courier.dedupCacheLock.Unlock()
}

// getCacheEntry safely retrieves a cache entry
func getCacheEntry(courier *Courier, envHash [hash.HashSize]byte) (*CourierBookKeeping, bool) {
	courier.dedupCacheLock.RLock()
	defer courier.dedupCacheLock.RUnlock()
	entry, exists := courier.dedupCache[envHash]
	return entry, exists
}

// verifyCacheEntry verifies that a cache entry exists and returns it
func verifyCacheEntry(t *testing.T, courier *Courier, envHash [hash.HashSize]byte) *CourierBookKeeping {
	entry, exists := getCacheEntry(courier, envHash)
	require.True(t, exists)
	require.NotNil(t, entry)
	return entry
}

// TestCourierCacheBasicOperations tests basic cache operations
func TestCourierCacheBasicOperations(t *testing.T) {
	courier := createTestCourier(t)

	// Test initial state - cache should be empty
	require.Equal(t, 0, len(courier.dedupCache))

	envHash := createTestEnvelopeHash()
	reply := createTestReply(&envHash, 0, "test-reply-payload", true)

	// Test CacheReply - first reply
	courier.CacheReply(reply)

	// Verify cache entry was created
	require.Equal(t, 1, len(courier.dedupCache))

	entry := verifyCacheEntry(t, courier, envHash)
	require.Equal(t, reply, entry.EnvelopeReplies[0])
	require.Nil(t, entry.EnvelopeReplies[1])
}

// TestCourierCacheDualReplies tests caching replies from both replicas
func TestCourierCacheDualReplies(t *testing.T) {
	courier := createTestCourier(t)
	envHash := createTestEnvelopeHash()

	// Set up the cache entry properly with both replica IDs first
	setupCacheEntry(courier, envHash, 1)

	reply1 := createTestReply(&envHash, 0, "reply-from-replica-0", true)
	reply2 := createTestReply(&envHash, 1, "reply-from-replica-1", true)

	// Cache first reply
	courier.CacheReply(reply1)

	// Verify first reply is cached
	entry := verifyCacheEntry(t, courier, envHash)
	require.Equal(t, reply1, entry.EnvelopeReplies[0])
	require.Nil(t, entry.EnvelopeReplies[1])

	// Cache second reply
	courier.CacheReply(reply2)

	// Verify both replies are cached
	entry, _ = getCacheEntry(courier, envHash)
	require.Equal(t, reply1, entry.EnvelopeReplies[0])
	require.Equal(t, reply2, entry.EnvelopeReplies[1])
}

// TestCourierCacheOverflow tests behavior when trying to cache more than 2 replies
func TestCourierCacheOverflow(t *testing.T) {
	courier := createTestCourier(t)
	envHash := createTestEnvelopeHash()

	// Set up the cache entry properly with both replica IDs first
	setupCacheEntry(courier, envHash, 1)

	reply1 := createTestReply(&envHash, 0, "reply-1", true)
	reply2 := createTestReply(&envHash, 1, "reply-2", true)
	reply3 := createTestReply(&envHash, 0, "reply-3-should-be-ignored", true)

	// Cache all three replies
	courier.CacheReply(reply1)
	courier.CacheReply(reply2)
	courier.CacheReply(reply3) // This should be ignored

	// Verify only first two replies are cached
	entry, _ := getCacheEntry(courier, envHash)
	require.Equal(t, reply1, entry.EnvelopeReplies[0])
	require.Equal(t, reply2, entry.EnvelopeReplies[1])
	require.NotEqual(t, reply3.EnvelopeReply, entry.EnvelopeReplies[0].EnvelopeReply)
}

// TestCourierCacheHandleOldMessage tests retrieving cached replies
func TestCourierCacheHandleOldMessage(t *testing.T) {
	courier := createTestCourier(t)
	envHash := createTestEnvelopeHash()

	// Set up the cache entry properly with both replica IDs first
	setupCacheEntry(courier, envHash, 1)

	reply1 := createTestReply(&envHash, 0, "cached-reply-0", true)
	reply2 := createTestReply(&envHash, 1, "cached-reply-1", true)

	// Cache both replies
	courier.CacheReply(reply1)
	courier.CacheReply(reply2)

	// Create courier envelope requesting reply index 0
	courierEnv := &pigeonhole.CourierEnvelope{
		ReplyIndex: 0,
	}

	// Get cached entry
	cacheEntry, _ := getCacheEntry(courier, envHash)

	// Test handleOldMessage for reply index 0
	reply := courier.handleOldMessage(cacheEntry, &envHash, courierEnv)

	// Verify the reply structure directly (skip trunnel parsing for now)
	require.NotNil(t, reply)
	require.NotNil(t, reply.EnvelopeReply)
	require.Equal(t, uint8(0), reply.EnvelopeReply.ReplyIndex)
	require.Equal(t, reply1.EnvelopeReply, reply.EnvelopeReply.Ciphertext)

	// Test handleOldMessage for reply index 1
	courierEnv.ReplyIndex = 1
	reply = courier.handleOldMessage(cacheEntry, &envHash, courierEnv)

	require.NotNil(t, reply)
	require.NotNil(t, reply.EnvelopeReply)
	require.Equal(t, uint8(1), reply.EnvelopeReply.ReplyIndex)
	require.Equal(t, reply2.EnvelopeReply, reply.EnvelopeReply.Ciphertext)
}

// TestCourierCacheFallbackBehavior tests fallback when requested reply index is not available
func TestCourierCacheFallbackBehavior(t *testing.T) {
	courier := createTestCourier(t)
	envHash := createTestEnvelopeHash()

	reply1 := createTestReply(&envHash, 1, "only-reply-from-replica-1", false)
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
	courierEnv := &pigeonhole.CourierEnvelope{
		ReplyIndex: 0,
	}

	cacheEntry, _ := getCacheEntry(courier, envHash)
	reply := courier.handleOldMessage(cacheEntry, &envHash, courierEnv)

	// Verify the reply structure directly (skip trunnel parsing for now)
	require.NotNil(t, reply)
	require.NotNil(t, reply.EnvelopeReply)
	// Should fallback to reply index 1 and update the reply index
	require.Equal(t, uint8(1), reply.EnvelopeReply.ReplyIndex)
	require.Equal(t, reply1.EnvelopeReply, reply.EnvelopeReply.Ciphertext)
}

// TestCourierCacheEmptyResponse tests behavior when no replies are cached
func TestCourierCacheEmptyResponse(t *testing.T) {
	courier := createTestCourier(t)
	envHash := createTestEnvelopeHash()

	// Create cache entry with no replies
	cacheEntry := &CourierBookKeeping{
		Epoch:           1,
		EnvelopeReplies: [2]*commands.ReplicaMessageReply{nil, nil},
	}

	courierEnv := &pigeonhole.CourierEnvelope{
		ReplyIndex: 0,
	}

	reply := courier.handleOldMessage(cacheEntry, &envHash, courierEnv)

	// Verify the reply structure directly (skip trunnel parsing for now)
	require.NotNil(t, reply)
	require.NotNil(t, reply.EnvelopeReply)
	require.Equal(t, uint8(0), reply.EnvelopeReply.ReplyIndex)
	require.Empty(t, reply.EnvelopeReply.Ciphertext)
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
	envHash := createTestEnvelopeHash()

	// Create multiple replies
	replies := make([]*commands.ReplicaMessageReply, 10)
	for i := 0; i < 10; i++ {
		replies[i] = createTestReply(&envHash, uint8(i%2), "concurrent-reply", true)
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
	entry := verifyCacheEntry(t, courier, envHash)

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
		envHashes[i] = createTestEnvelopeHashWithSuffix(string(rune('A' + i)))
	}

	// Cache replies for each envelope
	for i, envHash := range envHashes {
		reply := createTestReply(&envHash, uint8(i%2), "reply-for-envelope-"+string(rune('A'+i)), true)
		courier.CacheReply(reply)
	}

	// Verify all envelopes are cached separately
	require.Equal(t, 5, len(courier.dedupCache))

	for i, envHash := range envHashes {
		entry := verifyCacheEntry(t, courier, envHash)

		expectedReply := []byte("reply-for-envelope-" + string(rune('A'+i)))
		expectedReplicaID := uint8(i % 2)

		// CacheReply stores replies based on ReplicaID: replica 0 → slot 0, replica 1 → slot 1
		if expectedReplicaID == 0 {
			require.NotNil(t, entry.EnvelopeReplies[0])
			require.Equal(t, expectedReply, entry.EnvelopeReplies[0].EnvelopeReply)
			require.Equal(t, expectedReplicaID, entry.EnvelopeReplies[0].ReplicaID)
			require.Nil(t, entry.EnvelopeReplies[1])
		} else {
			require.NotNil(t, entry.EnvelopeReplies[1])
			require.Equal(t, expectedReply, entry.EnvelopeReplies[1].EnvelopeReply)
			require.Equal(t, expectedReplicaID, entry.EnvelopeReplies[1].ReplicaID)
			require.Nil(t, entry.EnvelopeReplies[0])
		}
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
	rawDoc, err := mockPKI.doc.MarshalCertificate()
	require.NoError(t, err)
	courier.server.PKI.SetDocumentForEpoch(testEpoch, mockPKI.doc, rawDoc)

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
	envHash := createTestEnvelopeHash()

	errorReply := createTestErrorReply(&envHash, 0, 1, "error-occurred", true)
	courier.CacheReply(errorReply)

	// Verify error reply is cached
	entry := verifyCacheEntry(t, courier, envHash)
	require.Equal(t, errorReply, entry.EnvelopeReplies[0])
	require.Equal(t, uint8(1), entry.EnvelopeReplies[0].ErrorCode)
}

// TestCourierCacheNilEnvelopeHash tests behavior with nil envelope hash
func TestCourierCacheNilEnvelopeHash(t *testing.T) {
	courier := createTestCourier(t)

	reply := createTestReply(nil, 0, "test-reply", false)

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
