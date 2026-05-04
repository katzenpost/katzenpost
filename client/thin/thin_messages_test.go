// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestThinClientErrorToString(t *testing.T) {
	tests := []struct {
		code     uint8
		contains string
	}{
		{ThinClientSuccess, "Success"},
		{ThinClientErrorConnectionLost, "Connection lost"},
		{ThinClientErrorTimeout, "Timeout"},
		{ThinClientErrorInvalidRequest, "Invalid request"},
		{ThinClientErrorInternalError, "Internal error"},
		{ThinClientErrorMaxRetries, "Maximum retries"},
		{ThinClientErrorInvalidChannel, "Invalid channel"},
		{ThinClientErrorChannelNotFound, "Channel not found"},
		{ThinClientErrorPermissionDenied, "Permission denied"},
		{ThinClientErrorInvalidPayload, "Invalid payload"},
		{ThinClientErrorServiceUnavailable, "Service unavailable"},
		{ThinClientErrorDuplicateCapability, "Duplicate capability"},
		{ThinClientErrorCourierCacheCorruption, "cache corruption"},
		{ThinClientPropagationError, "Propagation error"},
		{ThinClientErrorInvalidWriteCapability, "write capability"},
		{ThinClientErrorInvalidReadCapability, "read capability"},
		{ThinClientErrorInvalidResumeWriteChannelRequest, "resume write"},
		{ThinClientErrorInvalidResumeReadChannelRequest, "resume read"},
		{ThinClientImpossibleHashError, "hash error"},
		{ThinClientImpossibleNewWriteCapError, "write capability"},
		{ThinClientImpossibleNewStatefulWriterError, "stateful writer"},
		{ThinClientCapabilityAlreadyInUse, "already in use"},
		{ThinClientErrorMKEMDecryptionFailed, "MKEM"},
		{ThinClientErrorBACAPDecryptionFailed, "BACAP"},
		{ThinClientErrorStartResendingCancelled, "cancelled"},
		{ThinClientErrorInvalidTombstoneSig, "tombstone"},
	}

	for _, tt := range tests {
		result := ThinClientErrorToString(tt.code)
		require.Contains(t, result, tt.contains, "code %d", tt.code)
	}

	// Unknown code
	result := ThinClientErrorToString(255)
	require.Contains(t, result, "Unknown")
}

func TestIsExpectedOutcome(t *testing.T) {
	t.Run("tombstone is expected", func(t *testing.T) {
		require.True(t, IsExpectedOutcome(ErrTombstone))
	})

	t.Run("box not found is expected", func(t *testing.T) {
		require.True(t, IsExpectedOutcome(ErrBoxIDNotFound))
	})

	t.Run("box already exists is expected", func(t *testing.T) {
		require.True(t, IsExpectedOutcome(ErrBoxAlreadyExists))
	})

	t.Run("wrapped expected errors", func(t *testing.T) {
		wrapped := errors.Join(ErrTombstone, errors.New("extra context"))
		require.True(t, IsExpectedOutcome(wrapped))
	})

	t.Run("generic error is not expected", func(t *testing.T) {
		require.False(t, IsExpectedOutcome(errors.New("some error")))
	})

	t.Run("nil is not expected", func(t *testing.T) {
		require.False(t, IsExpectedOutcome(nil))
	})
}

func TestSessionTokenReplyString(t *testing.T) {
	r := &SessionTokenReply{Resumed: true}
	require.Contains(t, r.String(), "true")

	r2 := &SessionTokenReply{Resumed: false}
	require.Contains(t, r2.String(), "false")
}
