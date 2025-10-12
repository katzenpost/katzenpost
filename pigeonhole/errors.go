// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package pigeonhole

// Replica error codes - used in ReplicaReadReply and ReplicaWriteReply
const (
	ReplicaSuccess                uint8 = 0 // Operation completed successfully
	ReplicaErrorBoxIDNotFound     uint8 = 1 // Box ID/data not found
	ReplicaErrorInvalidBoxID      uint8 = 2 // Invalid BoxID format
	ReplicaErrorInvalidSignature  uint8 = 3 // Invalid or missing signature
	ReplicaErrorDatabaseFailure   uint8 = 4 // Database operation failed
	ReplicaErrorInvalidPayload    uint8 = 5 // Invalid payload data
	ReplicaErrorStorageFull       uint8 = 6 // Storage capacity exceeded
	ReplicaErrorInternalError     uint8 = 7 // Internal server error
	ReplicaErrorInvalidEpoch      uint8 = 8 // Invalid epoch
	ReplicaErrorReplicationFailed uint8 = 9 // Replication to other replicas failed
)

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
)
