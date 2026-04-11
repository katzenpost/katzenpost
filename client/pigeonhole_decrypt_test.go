// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

func TestClassifyReadReplyError(t *testing.T) {
	tests := []struct {
		name        string
		errorCode   uint8
		expectOK    bool
		expectTomb  bool
		expectError bool
	}{
		{
			name:      "success",
			errorCode: 0,
			expectOK:  true,
		},
		{
			name:       "tombstone passes through for signature validation",
			errorCode:  pigeonhole.ReplicaErrorTombstone,
			expectOK:   true,
			expectTomb: true,
		},
		{
			name:        "box not found",
			errorCode:   pigeonhole.ReplicaErrorBoxIDNotFound,
			expectError: true,
		},
		{
			name:        "box already exists",
			errorCode:   pigeonhole.ReplicaErrorBoxAlreadyExists,
			expectError: true,
		},
		{
			name:        "internal error",
			errorCode:   pigeonhole.ReplicaErrorInternalError,
			expectError: true,
		},
		{
			name:        "storage full",
			errorCode:   pigeonhole.ReplicaErrorStorageFull,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldProceed, isTombstone, err := classifyReadReplyError(tt.errorCode)
			if tt.expectError {
				require.False(t, shouldProceed)
				require.Error(t, err)
				re, ok := err.(*replicaError)
				require.True(t, ok)
				require.Equal(t, tt.errorCode, re.code)
			} else {
				require.True(t, shouldProceed)
				require.NoError(t, err)
				require.Equal(t, tt.expectTomb, isTombstone)
			}
		})
	}
}

func TestClassifyInnerMessage(t *testing.T) {
	t.Run("read reply success", func(t *testing.T) {
		msg := &pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 0,
			ReadReply: &pigeonhole.ReplicaReadReply{
				ErrorCode: 0,
				Payload:   []byte("data"),
			},
		}
		kind, err := classifyInnerMessage(msg)
		require.NoError(t, err)
		require.Equal(t, innerMessageRead, kind)
	})

	t.Run("write reply success", func(t *testing.T) {
		msg := &pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 1,
			WriteReply: &pigeonhole.ReplicaWriteReply{
				ErrorCode: 0,
			},
		}
		kind, err := classifyInnerMessage(msg)
		require.NoError(t, err)
		require.Equal(t, innerMessageWrite, kind)
	})

	t.Run("write reply with error", func(t *testing.T) {
		msg := &pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 1,
			WriteReply: &pigeonhole.ReplicaWriteReply{
				ErrorCode: pigeonhole.ReplicaErrorBoxAlreadyExists,
			},
		}
		kind, err := classifyInnerMessage(msg)
		require.NoError(t, err)
		require.Equal(t, innerMessageWrite, kind)
	})

	t.Run("unknown message type", func(t *testing.T) {
		msg := &pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 99,
		}
		_, err := classifyInnerMessage(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected inner message type")
	})

	t.Run("read type with nil ReadReply", func(t *testing.T) {
		msg := &pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 0,
			ReadReply:   nil,
		}
		_, err := classifyInnerMessage(msg)
		require.Error(t, err)
	})

	t.Run("write type with nil WriteReply", func(t *testing.T) {
		msg := &pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 1,
			WriteReply:  nil,
		}
		_, err := classifyInnerMessage(msg)
		require.Error(t, err)
	})
}

func TestClassifyWriteReply(t *testing.T) {
	t.Run("success returns nil", func(t *testing.T) {
		reply := &pigeonhole.ReplicaWriteReply{ErrorCode: 0}
		payload, err := classifyWriteReply(reply)
		require.NoError(t, err)
		require.Nil(t, payload)
	})

	t.Run("error returns replicaError", func(t *testing.T) {
		reply := &pigeonhole.ReplicaWriteReply{ErrorCode: pigeonhole.ReplicaErrorBoxAlreadyExists}
		_, err := classifyWriteReply(reply)
		require.Error(t, err)
		re, ok := err.(*replicaError)
		require.True(t, ok)
		require.Equal(t, pigeonhole.ReplicaErrorBoxAlreadyExists, re.code)
	})
}
