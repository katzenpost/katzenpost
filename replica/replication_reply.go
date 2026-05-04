// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"github.com/katzenpost/katzenpost/pigeonhole"
)

// replicationReplyAction classifies how an outgoing replica-to-replica
// ReplicaWriteReply should be treated by the sender.
type replicationReplyAction int

const (
	// replicationReplyOK means the peer successfully stored the write
	// (or already had it — BoxAlreadyExists is an idempotent outcome
	// during replication and not a durability failure).
	replicationReplyOK replicationReplyAction = iota

	// replicationReplyRetry means the peer rejected the write with a
	// transient error (database failure, internal error). Enqueue the
	// original ReplicaWrite for later retry via the connector's
	// existing retry queue.
	replicationReplyRetry

	// replicationReplyDrop means the peer rejected the write with a
	// permanent error (malformed signature, invalid box ID, etc.).
	// Retrying the same bytes won't help.
	replicationReplyDrop
)

// classifyReplicationReply maps a ReplicaWriteReply error code
// received by an outgoing replication peer into the sender's action.
// Unknown codes default to Drop — we don't know how to recover from
// them so we don't silently keep retrying.
func classifyReplicationReply(code uint8) replicationReplyAction {
	switch code {
	case pigeonhole.ReplicaSuccess,
		pigeonhole.ReplicaErrorBoxAlreadyExists:
		return replicationReplyOK
	case pigeonhole.ReplicaErrorDatabaseFailure,
		pigeonhole.ReplicaErrorInternalError:
		return replicationReplyRetry
	default:
		return replicationReplyDrop
	}
}
