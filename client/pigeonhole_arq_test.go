// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

func TestCourierEnvelopeErrorToThinError(t *testing.T) {
	// Every courier envelope error must map clear of the replica error range
	// (1-11), so a courier rejection is never read as a replica error.
	cases := map[uint8]uint8{
		pigeonhole.EnvelopeErrorSuccess:          thin.ThinClientSuccess,
		pigeonhole.EnvelopeErrorInvalidEnvelope:  thin.ThinClientErrorCourierInvalidEnvelope,
		pigeonhole.EnvelopeErrorCacheCorruption:  thin.ThinClientErrorCourierCacheCorruption,
		pigeonhole.EnvelopeErrorPropagationError: thin.ThinClientPropagationError,
		pigeonhole.EnvelopeErrorInvalidEpoch:     thin.ThinClientErrorCourierInvalidEpoch,
	}
	for courierCode, want := range cases {
		got := courierEnvelopeErrorToThinError(courierCode)
		require.Equal(t, want, got, "courier code %d", courierCode)
		if courierCode != pigeonhole.EnvelopeErrorSuccess {
			require.Greater(t, got, uint8(11), "courier code %d mapped into replica range", courierCode)
		}
	}
	// The collision we are guarding against: courier InvalidEpoch and replica
	// DatabaseFailure share source value 4, but must not share the wire code.
	require.NotEqual(t, pigeonhole.ReplicaErrorDatabaseFailure,
		courierEnvelopeErrorToThinError(pigeonhole.EnvelopeErrorInvalidEpoch))
	// Unknown courier codes also stay out of the replica range.
	require.Greater(t, courierEnvelopeErrorToThinError(200), uint8(11))
}

func TestComputeARQStateTransition(t *testing.T) {
	tests := []struct {
		name                         string
		state                        ARQState
		replyType                    uint8
		errorCode                    uint8
		isRead                       bool
		noIdempotentBoxAlreadyExists bool
		expectedAction               ARQAction
		expectedNewState             ARQState
		expectedShouldRemove         bool
	}{
		// WaitingForACK + ACK + write (default idempotent) → complete immediately
		{
			name:                         "write ACK idempotent",
			state:                        ARQStateWaitingForACK,
			replyType:                    pigeonhole.ReplyTypeACK,
			isRead:                       false,
			noIdempotentBoxAlreadyExists: false,
			expectedAction:               ARQActionComplete,
			expectedNewState:             ARQStateWaitingForACK,
			expectedShouldRemove:         true,
		},
		// WaitingForACK + ACK + write (non-idempotent) → need payload
		{
			name:                         "write ACK non-idempotent needs payload",
			state:                        ARQStateWaitingForACK,
			replyType:                    pigeonhole.ReplyTypeACK,
			isRead:                       false,
			noIdempotentBoxAlreadyExists: true,
			expectedAction:               ARQActionSendNewSURB,
			expectedNewState:             ARQStateACKReceived,
			expectedShouldRemove:         false,
		},
		// WaitingForACK + ACK + read → need payload
		{
			name:                 "read ACK needs payload",
			state:                ARQStateWaitingForACK,
			replyType:            pigeonhole.ReplyTypeACK,
			isRead:               true,
			expectedAction:       ARQActionSendNewSURB,
			expectedNewState:     ARQStateACKReceived,
			expectedShouldRemove: false,
		},
		// WaitingForACK + Payload → unexpected but handle it (skip to payload)
		{
			name:                 "unexpected payload while waiting for ACK",
			state:                ARQStateWaitingForACK,
			replyType:            pigeonhole.ReplyTypePayload,
			isRead:               true,
			expectedAction:       ARQActionHandlePayload,
			expectedNewState:     ARQStatePayloadReceived,
			expectedShouldRemove: false,
		},
		// ACKReceived + Payload → handle payload
		{
			name:                 "payload received after ACK",
			state:                ARQStateACKReceived,
			replyType:            pigeonhole.ReplyTypePayload,
			isRead:               true,
			expectedAction:       ARQActionHandlePayload,
			expectedNewState:     ARQStatePayloadReceived,
			expectedShouldRemove: false,
		},
		// ACKReceived + ACK (duplicate) → keep polling
		{
			name:                 "duplicate ACK data not ready",
			state:                ARQStateACKReceived,
			replyType:            pigeonhole.ReplyTypeACK,
			isRead:               true,
			expectedAction:       ARQActionSendNewSURB,
			expectedNewState:     ARQStateACKReceived,
			expectedShouldRemove: false,
		},
		// PayloadReceived + anything → ignore (terminal state)
		{
			name:                 "terminal state ignores ACK",
			state:                ARQStatePayloadReceived,
			replyType:            pigeonhole.ReplyTypeACK,
			isRead:               true,
			expectedAction:       ARQActionIgnore,
			expectedNewState:     ARQStatePayloadReceived,
			expectedShouldRemove: false,
		},
		{
			name:                 "terminal state ignores payload",
			state:                ARQStatePayloadReceived,
			replyType:            pigeonhole.ReplyTypePayload,
			isRead:               true,
			expectedAction:       ARQActionIgnore,
			expectedNewState:     ARQStatePayloadReceived,
			expectedShouldRemove: false,
		},
		// Error code in reply → error action, remove from tracking
		{
			name:                 "error code removes from tracking",
			state:                ARQStateWaitingForACK,
			replyType:            pigeonhole.ReplyTypeACK,
			errorCode:            pigeonhole.EnvelopeErrorPropagationError,
			isRead:               false,
			expectedAction:       ARQActionError,
			expectedNewState:     ARQStateWaitingForACK,
			expectedShouldRemove: true,
		},
		{
			name:                 "error code during ACKReceived",
			state:                ARQStateACKReceived,
			replyType:            pigeonhole.ReplyTypePayload,
			errorCode:            pigeonhole.EnvelopeErrorCacheCorruption,
			isRead:               true,
			expectedAction:       ARQActionError,
			expectedNewState:     ARQStateACKReceived,
			expectedShouldRemove: true,
		},
		// Write ACK non-idempotent with payload → handle payload
		{
			name:                         "write non-idempotent payload after ACK",
			state:                        ARQStateACKReceived,
			replyType:                    pigeonhole.ReplyTypePayload,
			isRead:                       false,
			noIdempotentBoxAlreadyExists: true,
			expectedAction:               ARQActionHandlePayload,
			expectedNewState:             ARQStatePayloadReceived,
			expectedShouldRemove:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := computeARQStateTransition(
				tt.state,
				tt.replyType,
				tt.errorCode,
				tt.isRead,
				tt.noIdempotentBoxAlreadyExists,
			)
			require.Equal(t, tt.expectedAction, result.Action, "wrong action")
			require.Equal(t, tt.expectedNewState, result.NewState, "wrong new state")
			require.Equal(t, tt.expectedShouldRemove, result.ShouldRemove, "wrong shouldRemove")
			if tt.errorCode != 0 {
				require.Equal(t, tt.errorCode, result.ErrorCode, "wrong error code")
			}
		})
	}
}
