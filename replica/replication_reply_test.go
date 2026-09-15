// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

func TestClassifyReplicationReply(t *testing.T) {
	tests := []struct {
		name string
		code uint8
		want replicationReplyAction
	}{
		{"Success is OK", pigeonhole.ReplicaSuccess, replicationReplyOK},
		{"BoxAlreadyExists is OK (idempotent replication)", pigeonhole.ReplicaErrorBoxAlreadyExists, replicationReplyOK},

		{"DatabaseFailure is retryable", pigeonhole.ReplicaErrorDatabaseFailure, replicationReplyRetry},
		{"InternalError is retryable", pigeonhole.ReplicaErrorInternalError, replicationReplyRetry},

		// Permanent errors — the write bytes themselves are no good.
		{"InvalidBoxID is a drop", pigeonhole.ReplicaErrorInvalidBoxID, replicationReplyDrop},
		{"InvalidSignature is a drop", pigeonhole.ReplicaErrorInvalidSignature, replicationReplyDrop},
		{"InvalidPayload is a drop", pigeonhole.ReplicaErrorInvalidPayload, replicationReplyDrop},
		{"BoxIDNotFound is a drop (nonsense on a write reply)", pigeonhole.ReplicaErrorBoxIDNotFound, replicationReplyDrop},
		{"InvalidEpoch is a drop", pigeonhole.ReplicaErrorInvalidEpoch, replicationReplyDrop},
		{"ReplicationFailed is a drop", pigeonhole.ReplicaErrorReplicationFailed, replicationReplyDrop},
		{"Tombstone is a drop (peer reporting data state, not a write outcome)", pigeonhole.ReplicaErrorTombstone, replicationReplyDrop},

		// StorageFull is a judgment call — retry could help if the
		// peer reclaims space, but is more likely to keep failing.
		// Tracking it as a Drop keeps this table honest; if we later
		// decide to retry, we can flip it.
		{"StorageFull is a drop", pigeonhole.ReplicaErrorStorageFull, replicationReplyDrop},

		// Unknown codes must not silently Retry — that's how we end up
		// with infinite loops when the peer introduces a new error
		// code the classifier hasn't been taught.
		{"Unknown code 200 is a drop", 200, replicationReplyDrop},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyReplicationReply(tt.code)
			require.Equal(t, tt.want, got)
		})
	}
}
