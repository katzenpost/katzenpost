// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

// TestClassifyReplicaErrorForCopyRead pins the temporary-vs-permanent
// reaction the courier's Copy command read path takes for each
// non-success replica error code. Temporary means same-replica retry
// with backoff; Permanent means failover to the shard peer.
func TestClassifyReplicaErrorForCopyRead(t *testing.T) {
	cases := []struct {
		code     uint8
		expected replicaErrorCategory
		name     string
	}{
		// Conditions that may resolve given time or a retry.
		{pigeonhole.ReplicaErrorBoxIDNotFound, replicaErrorTemporary, "BoxIDNotFound"},
		{pigeonhole.ReplicaErrorStorageFull, replicaErrorTemporary, "StorageFull"},
		{pigeonhole.ReplicaErrorDatabaseFailure, replicaErrorTemporary, "DatabaseFailure"},
		{pigeonhole.ReplicaErrorInternalError, replicaErrorTemporary, "InternalError"},
		{pigeonhole.ReplicaErrorReplicationFailed, replicaErrorTemporary, "ReplicationFailed"},

		// Conditions where this replica will not serve the request — the
		// shard peer may, so failover; if it also fails, abort.
		{pigeonhole.ReplicaErrorInvalidBoxID, replicaErrorPermanent, "InvalidBoxID"},
		{pigeonhole.ReplicaErrorInvalidSignature, replicaErrorPermanent, "InvalidSignature"},
		{pigeonhole.ReplicaErrorInvalidPayload, replicaErrorPermanent, "InvalidPayload"},
		{pigeonhole.ReplicaErrorInvalidEpoch, replicaErrorPermanent, "InvalidEpoch"},
		{pigeonhole.ReplicaErrorBoxAlreadyExists, replicaErrorPermanent, "BoxAlreadyExists"},
		{pigeonhole.ReplicaErrorTombstone, replicaErrorPermanent, "Tombstone"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, classifyReplicaErrorForCopyRead(tc.code),
				"code=%d (%s)", tc.code, tc.name)
		})
	}
}

// TestClassifyReplicaErrorForCopyReadUnknown ensures unrecognised
// codes fail closed (treated as permanent) so a future replica
// change can't silently introduce an unbounded same-replica loop.
func TestClassifyReplicaErrorForCopyReadUnknown(t *testing.T) {
	for _, code := range []uint8{42, 100, 200, 255} {
		require.Equal(t, replicaErrorPermanent,
			classifyReplicaErrorForCopyRead(code),
			"unknown code %d must classify as permanent", code)
	}
}
