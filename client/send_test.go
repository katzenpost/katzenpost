// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func TestValidateSendMessageRequest(t *testing.T) {
	destHash := new([32]byte)
	recipient := []byte("queue")
	payload := []byte("hello")
	maxPayloadLen := 1000

	t.Run("valid", func(t *testing.T) {
		err := validateSendMessageRequest(destHash, recipient, payload, maxPayloadLen)
		require.NoError(t, err)
	})

	t.Run("nil destination hash", func(t *testing.T) {
		err := validateSendMessageRequest(nil, recipient, payload, maxPayloadLen)
		require.Error(t, err)
		require.Contains(t, err.Error(), "DestinationIdHash")
	})

	t.Run("empty recipient", func(t *testing.T) {
		err := validateSendMessageRequest(destHash, nil, payload, maxPayloadLen)
		require.Error(t, err)
		require.Contains(t, err.Error(), "recipient")
	})

	t.Run("recipient too long", func(t *testing.T) {
		longRecipient := make([]byte, sConstants.RecipientIDLength+1)
		err := validateSendMessageRequest(destHash, longRecipient, payload, maxPayloadLen)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid recipient")
	})

	t.Run("payload too large", func(t *testing.T) {
		bigPayload := make([]byte, maxPayloadLen+1)
		err := validateSendMessageRequest(destHash, recipient, bigPayload, maxPayloadLen)
		require.Error(t, err)
		require.Contains(t, err.Error(), "too large")
	})

	t.Run("empty payload is valid", func(t *testing.T) {
		err := validateSendMessageRequest(destHash, recipient, []byte{}, maxPayloadLen)
		require.NoError(t, err)
	})
}

func TestCheckSequence(t *testing.T) {
	t.Run("matching sequence", func(t *testing.T) {
		err := checkSequence(42, 42)
		require.NoError(t, err)
	})

	t.Run("zero sequence", func(t *testing.T) {
		err := checkSequence(0, 0)
		require.NoError(t, err)
	})

	t.Run("mismatch", func(t *testing.T) {
		err := checkSequence(5, 3)
		require.Error(t, err)
		var pe *ProtocolError
		require.ErrorAs(t, err, &pe)
	})
}
