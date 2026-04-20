// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import "github.com/katzenpost/katzenpost/pigeonhole"

// replicaErrorCategory tells the Copy command how to react to a
// non-success replica error code reported via ReplicaMessageReply.
type replicaErrorCategory int

const (
	// replicaErrorTemporary: the underlying condition could change
	// (replication lag, momentary DB issue, transient out-of-space).
	// Retry the same replica with backoff a bounded number of times.
	replicaErrorTemporary replicaErrorCategory = iota

	// replicaErrorPermanent: this replica cannot serve the request and
	// retrying it will not help. Failover to the shard peer; if that
	// also returns a permanent (or exhausted-temporary) error, abort
	// the Copy operation.
	replicaErrorPermanent
)

// classifyReplicaErrorForCopyRead maps a non-zero replica ErrorCode
// to a temporary-or-permanent reaction for the Copy command's read
// path. Callers must check for ReplicaSuccess (code == 0) themselves
// before consulting this function. Unknown codes fail closed — they
// are treated as permanent so a future replica change cannot silently
// introduce an unbounded same-replica retry loop.
func classifyReplicaErrorForCopyRead(code uint8) replicaErrorCategory {
	switch code {
	case pigeonhole.ReplicaErrorBoxIDNotFound,    // replication lag, or future write
		pigeonhole.ReplicaErrorStorageFull,       // disk pressure may ease
		pigeonhole.ReplicaErrorDatabaseFailure,   // DB momentarily unavailable
		pigeonhole.ReplicaErrorInternalError,     // unspecified replica-side hiccup
		pigeonhole.ReplicaErrorReplicationFailed: // peer-replica blip
		return replicaErrorTemporary
	}
	return replicaErrorPermanent
}
