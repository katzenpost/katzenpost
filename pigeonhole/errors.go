// errors.go - Centralized error codes and error handling for Katzenpost Pigeonhole
// Copyright (C) 2024  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package pigeonhole

import "fmt"

// Error message constants to avoid duplication
const (
	errorMsgInternalError = "Internal error"
)

// Replica error codes - used in ReplicaReadReply and ReplicaWriteReply
const (
	ReplicaErrorSuccess           uint8 = 0  // Operation completed successfully
	ReplicaErrorNotFound          uint8 = 1  // Box/data not found
	ReplicaErrorInvalidBoxID      uint8 = 2  // Invalid BoxID format
	ReplicaErrorInvalidSignature  uint8 = 3  // Invalid or missing signature
	ReplicaErrorDatabaseError     uint8 = 4  // Database operation failed
	ReplicaErrorInvalidPayload    uint8 = 5  // Invalid payload data
	ReplicaErrorStorageFull       uint8 = 6  // Storage capacity exceeded
	ReplicaErrorPermissionDenied  uint8 = 7  // Access denied
	ReplicaErrorInternalError     uint8 = 8  // Internal server error
	ReplicaErrorInvalidEpoch      uint8 = 9  // Invalid epoch
	ReplicaErrorReplicationFailed uint8 = 10 // Replication to other replicas failed
)

// Courier copy command error codes
const (
	CopyErrorSuccess           uint8 = 0 // Copy operation completed successfully
	CopyErrorInvalidWriteCap   uint8 = 1 // Invalid WriteCap provided
	CopyErrorReadCapDerivation uint8 = 2 // Failed to derive ReadCap from WriteCap
	CopyErrorRead              uint8 = 3 // Read operation failed
	CopyErrorEmptySequence     uint8 = 4 // BACAP sequence is empty
	CopyErrorBACAPDecryption   uint8 = 5 // BACAP decryption failed

	CopyErrorStreamingDecoder uint8 = 7  // Streaming decoder failed
	CopyErrorReplicaTimeout   uint8 = 8  // Replica operation timed out
	CopyErrorMKEMDecryption   uint8 = 9  // MKEM decryption failed
	CopyErrorTombstoneWrite   uint8 = 10 // Failed to write tombstone
	CopyErrorReplicaNotFound  uint8 = 11 // Replica data not found (proxied from replica)
	CopyErrorReplicaDatabase  uint8 = 12 // Replica database error (proxied from replica)
	CopyErrorReplicaInternal  uint8 = 13 // Replica internal error (proxied from replica)
)

// Courier envelope operation error codes
const (
	EnvelopeErrorSuccess            uint8 = 0  // Envelope operation completed successfully
	EnvelopeErrorInvalidEnvelope    uint8 = 1  // Invalid envelope format
	EnvelopeErrorNilEnvelopeHash    uint8 = 2  // Envelope hash is nil
	EnvelopeErrorNilDEKElements     uint8 = 3  // DEK elements are nil
	EnvelopeErrorInvalidReplicaID   uint8 = 4  // Invalid replica ID
	EnvelopeErrorReplicaTimeout     uint8 = 5  // Replica operation timed out
	EnvelopeErrorConnectionFailure  uint8 = 6  // Connection to replica failed
	EnvelopeErrorCacheCorruption    uint8 = 7  // Cache data corruption detected
	EnvelopeErrorPKIUnavailable     uint8 = 8  // PKI document unavailable
	EnvelopeErrorInvalidEpoch       uint8 = 9  // Invalid epoch
	EnvelopeErrorMKEMFailure        uint8 = 10 // MKEM operation failed
	EnvelopeErrorReplicaUnavailable uint8 = 11 // Replica is unavailable
	EnvelopeErrorInternalError      uint8 = 12 // Internal courier error
)

// General courier error codes
const (
	CourierErrorSuccess        uint8 = 0 // Operation completed successfully
	CourierErrorInvalidCommand uint8 = 1 // Invalid command received

	CourierErrorDispatchFailure uint8 = 3 // Failed to dispatch to replica
	CourierErrorConnectionLost  uint8 = 4 // Connection to replica lost
	CourierErrorInternalError   uint8 = 5 // Internal courier error
)

// Client error codes
const (
	ClientErrorSuccess        uint8 = 0 // Operation completed successfully
	ClientErrorInvalidRequest uint8 = 1 // Invalid request format
	ClientErrorConnectionLost uint8 = 2 // Connection to courier lost
	ClientErrorTimeout        uint8 = 3 // Operation timed out
	ClientErrorInternalError  uint8 = 4 // Internal client error
	ClientErrorMaxRetries     uint8 = 5 // Maximum retries exceeded
)

// ReplicaErrorToString returns a human-readable string for replica error codes
func ReplicaErrorToString(errorCode uint8) string {
	switch errorCode {
	case ReplicaErrorSuccess:
		return "Success"
	case ReplicaErrorNotFound:
		return "Data not found"
	case ReplicaErrorInvalidBoxID:
		return "Invalid BoxID"
	case ReplicaErrorInvalidSignature:
		return "Invalid signature"
	case ReplicaErrorDatabaseError:
		return "Database error"
	case ReplicaErrorInvalidPayload:
		return "Invalid payload"
	case ReplicaErrorStorageFull:
		return "Storage full"
	case ReplicaErrorPermissionDenied:
		return "Permission denied"
	case ReplicaErrorInternalError:
		return errorMsgInternalError
	case ReplicaErrorInvalidEpoch:
		return "Invalid epoch"
	case ReplicaErrorReplicationFailed:
		return "Replication failed"
	default:
		return fmt.Sprintf("Unknown replica error code: %d", errorCode)
	}
}

// CopyErrorToString returns a human-readable string for copy error codes
func CopyErrorToString(errorCode uint8) string {
	switch errorCode {
	case CopyErrorSuccess:
		return "Success"
	case CopyErrorInvalidWriteCap:
		return "Invalid WriteCap"
	case CopyErrorReadCapDerivation:
		return "ReadCap derivation failed"
	case CopyErrorRead:
		return "Read operation failed"
	case CopyErrorEmptySequence:
		return "Empty sequence"
	case CopyErrorBACAPDecryption:
		return "BACAP decryption failed"

	case CopyErrorStreamingDecoder:
		return "Streaming decoder failed"
	case CopyErrorReplicaTimeout:
		return "Replica timeout"
	case CopyErrorMKEMDecryption:
		return "MKEM decryption failed"
	case CopyErrorTombstoneWrite:
		return "Tombstone write failed"
	case CopyErrorReplicaNotFound:
		return "Replica data not found"
	case CopyErrorReplicaDatabase:
		return "Replica database error"
	case CopyErrorReplicaInternal:
		return "Replica internal error"
	default:
		return fmt.Sprintf("Unknown copy error code: %d", errorCode)
	}
}

// EnvelopeErrorToString returns a human-readable string for envelope error codes
func EnvelopeErrorToString(errorCode uint8) string {
	switch errorCode {
	case EnvelopeErrorSuccess:
		return "Success"
	case EnvelopeErrorInvalidEnvelope:
		return "Invalid envelope"
	case EnvelopeErrorNilEnvelopeHash:
		return "Nil envelope hash"
	case EnvelopeErrorNilDEKElements:
		return "Nil DEK elements"
	case EnvelopeErrorInvalidReplicaID:
		return "Invalid replica ID"
	case EnvelopeErrorReplicaTimeout:
		return "Replica timeout"
	case EnvelopeErrorConnectionFailure:
		return "Connection failure"
	case EnvelopeErrorCacheCorruption:
		return "Cache corruption"
	case EnvelopeErrorPKIUnavailable:
		return "PKI unavailable"
	case EnvelopeErrorInvalidEpoch:
		return "Invalid epoch"
	case EnvelopeErrorMKEMFailure:
		return "MKEM failure"
	case EnvelopeErrorReplicaUnavailable:
		return "Replica unavailable"
	case EnvelopeErrorInternalError:
		return errorMsgInternalError
	default:
		return fmt.Sprintf("Unknown envelope error code: %d", errorCode)
	}
}

// CourierErrorToString returns a human-readable string for general courier error codes
func CourierErrorToString(errorCode uint8) string {
	switch errorCode {
	case CourierErrorSuccess:
		return "Success"
	case CourierErrorInvalidCommand:
		return "Invalid command"

	case CourierErrorDispatchFailure:
		return "Dispatch failure"
	case CourierErrorConnectionLost:
		return "Connection lost"
	case CourierErrorInternalError:
		return errorMsgInternalError
	default:
		return fmt.Sprintf("Unknown courier error code: %d", errorCode)
	}
}

// ClientErrorToString returns a human-readable string for client error codes
func ClientErrorToString(errorCode uint8) string {
	switch errorCode {
	case ClientErrorSuccess:
		return "Success"
	case ClientErrorInvalidRequest:
		return "Invalid request"
	case ClientErrorConnectionLost:
		return "Connection lost"
	case ClientErrorTimeout:
		return "Timeout"
	case ClientErrorInternalError:
		return errorMsgInternalError
	case ClientErrorMaxRetries:
		return "Maximum retries exceeded"
	default:
		return fmt.Sprintf("Unknown client error code: %d", errorCode)
	}
}

// MapReplicaErrorToCopyError maps replica error codes to copy error codes for proxying
func MapReplicaErrorToCopyError(replicaError uint8) uint8 {
	switch replicaError {
	case ReplicaErrorSuccess:
		return CopyErrorSuccess
	case ReplicaErrorNotFound:
		return CopyErrorReplicaNotFound
	case ReplicaErrorDatabaseError:
		return CopyErrorReplicaDatabase
	case ReplicaErrorInternalError, ReplicaErrorInvalidBoxID, ReplicaErrorInvalidSignature,
		ReplicaErrorInvalidPayload, ReplicaErrorStorageFull, ReplicaErrorPermissionDenied,
		ReplicaErrorInvalidEpoch, ReplicaErrorReplicationFailed:
		return CopyErrorReplicaInternal
	default:
		return CopyErrorReplicaInternal
	}
}

// MapReplicaErrorToEnvelopeError maps replica error codes to envelope error codes for proxying
func MapReplicaErrorToEnvelopeError(replicaError uint8) uint8 {
	switch replicaError {
	case ReplicaErrorSuccess:
		return EnvelopeErrorSuccess
	case ReplicaErrorNotFound:
		return EnvelopeErrorReplicaUnavailable
	case ReplicaErrorDatabaseError, ReplicaErrorInternalError:
		return EnvelopeErrorInternalError
	case ReplicaErrorInvalidEpoch:
		return EnvelopeErrorInvalidEpoch
	default:
		return EnvelopeErrorInternalError
	}
}
