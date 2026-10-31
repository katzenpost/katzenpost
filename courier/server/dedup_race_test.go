// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// TestCachePollNoRaceWithCacheReply runs client polls for an envelope
// concurrently with replica replies being cached for it. Under -race a
// poll that reads the dedupCache entry outside dedupCacheLock trips the
// detector.
func TestCachePollNoRaceWithCacheReply(t *testing.T) {
	courier := createTestCourier(t)
	courier.Stop()
	defer courier.Halt()

	epoch, _, _ := replicaCommon.ReplicaNow()
	newEnvelope := func() *pigeonhole.CourierEnvelope {
		return &pigeonhole.CourierEnvelope{
			Epoch:                epoch,
			IntermediateReplicas: [2]uint8{0, 1},
			SenderPubkey:         []byte("race-sender-pubkey"),
			Ciphertext:           []byte("race-ciphertext"),
		}
	}
	envHash := newEnvelope().EnvelopeHash()

	reply := courier.cacheHandleCourierEnvelope(0, newEnvelope())
	require.Equal(t, pigeonhole.ReplyTypeACK, reply.EnvelopeReply.ReplyType)

	const iterations = 2000
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			courier.CacheReply(createTestErrorReply(envHash, uint8(i%2), pigeonhole.ReplicaErrorBoxIDNotFound, "not-found"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			env := newEnvelope()
			env.ReplyIndex = uint8(i % 2)
			if courier.cacheHandleCourierEnvelope(0, env) == nil {
				t.Error("poll returned nil reply")
				return
			}
		}
	}()
	wg.Wait()
}
