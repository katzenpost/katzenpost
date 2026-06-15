// copy_pki_gap_test.go - Tests for shard-document resolution across an epoch gap.
// Copyright (C) 2026  The Katzenpost Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

// TestPKIDocForShardingFallback verifies that shard resolution falls back to the
// most recently cached document during the window after an epoch rollover, when
// the current epoch's document has not yet been fetched. Without this, the Copy
// read and tombstone paths would refuse to operate during that gap even though
// the previous document is cached and shard membership is unchanged.
func TestPKIDocForShardingFallback(t *testing.T) {
	courier := createTestCourier(t)
	// Stop the background PKI worker so the cache is solely under test control.
	courier.server.PKI.Halt()

	now, _, _ := epochtime.Now()

	// Nothing cached: the genuine no-document case is still surfaced as nil.
	require.Nil(t, courier.pkiDocForSharding())

	// Post-rollover gap: only the previous epoch's document is cached, so the
	// current-epoch lookup is nil but the fallback returns the previous one.
	prev := &pki.Document{Epoch: now - 1}
	courier.server.PKI.SetDocumentForEpoch(now-1, prev, []byte("prev"))
	require.Nil(t, courier.server.PKI.PKIDocument(), "current epoch must be absent")
	got := courier.pkiDocForSharding()
	require.NotNil(t, got, "must fall back to the cached previous document")
	require.Equal(t, now-1, got.Epoch)

	// Once the current epoch's document arrives, it is preferred.
	cur := &pki.Document{Epoch: now}
	courier.server.PKI.SetDocumentForEpoch(now, cur, []byte("cur"))
	got = courier.pkiDocForSharding()
	require.NotNil(t, got)
	require.Equal(t, now, got.Epoch)
}
