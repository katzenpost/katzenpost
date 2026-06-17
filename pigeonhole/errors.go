// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package pigeonhole

// Replica error codes - used in ReplicaReadReply and ReplicaWriteReply
const (
	ReplicaSuccess                uint8 = 0  // Operation completed successfully
	ReplicaErrorBoxIDNotFound     uint8 = 1  // Box ID/data not found
	ReplicaErrorInvalidBoxID      uint8 = 2  // Invalid BoxID format
	ReplicaErrorInvalidSignature  uint8 = 3  // Invalid or missing signature
	ReplicaErrorDatabaseFailure   uint8 = 4  // Database operation failed
	ReplicaErrorInvalidPayload    uint8 = 5  // Invalid payload data
	ReplicaErrorStorageFull       uint8 = 6  // Storage capacity exceeded
	ReplicaErrorInternalError     uint8 = 7  // Internal server error
	ReplicaErrorInvalidEpoch      uint8 = 8  // Invalid epoch
	ReplicaErrorReplicationFailed uint8 = 9  // Replication to other replicas failed
	ReplicaErrorBoxAlreadyExists  uint8 = 10 // Box already exists (writes are immutable)
	ReplicaErrorTombstone         uint8 = 11 // Box contains a tombstone (intentional deletion)
)

// ReplicaErrorToString returns a short human-readable description of a replica
// error code, so logs and errors can name the condition (for example "box not
// found") rather than printing a bare numeric code.
func ReplicaErrorToString(code uint8) string {
	switch code {
	case ReplicaSuccess:
		return "success"
	case ReplicaErrorBoxIDNotFound:
		return "box not found"
	case ReplicaErrorInvalidBoxID:
		return "invalid box ID"
	case ReplicaErrorInvalidSignature:
		return "invalid signature"
	case ReplicaErrorDatabaseFailure:
		return "database failure"
	case ReplicaErrorInvalidPayload:
		return "invalid payload"
	case ReplicaErrorStorageFull:
		return "storage full"
	case ReplicaErrorInternalError:
		return "internal error"
	case ReplicaErrorInvalidEpoch:
		return "invalid epoch"
	case ReplicaErrorReplicationFailed:
		return "replication failed"
	case ReplicaErrorBoxAlreadyExists:
		return "box already exists"
	case ReplicaErrorTombstone:
		return "tombstone"
	default:
		return "unknown replica error"
	}
}

// Courier envelope reply type constants
const (
	// ReplyType field values for CourierEnvelopeReply
	ReplyTypeACK     uint8 = 0 // ACK - Request received and dispatched to replicas
	ReplyTypePayload uint8 = 1 // Payload Reply - Read operation completed with data
)

// Courier envelope operation error codes
const (
	EnvelopeErrorSuccess          uint8 = 0 // Operation completed successfully
	EnvelopeErrorInvalidEnvelope  uint8 = 1 // Invalid envelope format
	EnvelopeErrorCacheCorruption  uint8 = 2 // Cache data corruption detected
	EnvelopeErrorPropagationError uint8 = 3 // Error propagating request to replicas
	EnvelopeErrorInvalidEpoch     uint8 = 4 // Envelope's replica epoch is outside the accepted window
)

// CopyCommandReply status codes. The Copy command is async: the courier
// acknowledges receipt immediately with InProgress and processes the
// work in a background goroutine; the client polls the same Copy
// command (same WriteCap) until it receives a terminal Succeeded or
// Failed status.
const (
	CopyStatusSucceeded  uint8 = 0 // All destination writes completed.
	CopyStatusInProgress uint8 = 1 // Courier accepted the command; processing continues.
	CopyStatusFailed     uint8 = 2 // Processing aborted; see ErrorCode + FailedEnvelopeIndex.
)
