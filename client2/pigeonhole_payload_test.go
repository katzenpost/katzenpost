// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

func TestDeterminePayloadErrorAction(t *testing.T) {
	boxNotFound := &replicaError{code: pigeonhole.ReplicaErrorBoxIDNotFound}
	boxAlreadyExists := &replicaError{code: pigeonhole.ReplicaErrorBoxAlreadyExists}
	tombstone := &replicaError{code: pigeonhole.ReplicaErrorTombstone}

	t.Run("read BoxIDNotFound retries by default", func(t *testing.T) {
		action := determinePayloadErrorAction(boxNotFound, true, false, false)
		require.Equal(t, payloadActionRetry, action)
	})

	t.Run("read BoxIDNotFound with NoRetry returns error", func(t *testing.T) {
		action := determinePayloadErrorAction(boxNotFound, true, true, false)
		require.Equal(t, payloadActionReturnError, action)
	})

	t.Run("write BoxAlreadyExists idempotent success by default", func(t *testing.T) {
		action := determinePayloadErrorAction(boxAlreadyExists, false, false, false)
		require.Equal(t, payloadActionIdempotentSuccess, action)
	})

	t.Run("write BoxAlreadyExists with NoIdempotent returns error", func(t *testing.T) {
		action := determinePayloadErrorAction(boxAlreadyExists, false, false, true)
		require.Equal(t, payloadActionReturnError, action)
	})

	t.Run("tombstone returns error", func(t *testing.T) {
		action := determinePayloadErrorAction(tombstone, true, false, false)
		require.Equal(t, payloadActionReturnError, action)
	})

	t.Run("MKEM decryption failure returns error", func(t *testing.T) {
		action := determinePayloadErrorAction(errMKEMDecryptionFailed, true, false, false)
		require.Equal(t, payloadActionReturnError, action)
	})

	t.Run("BACAP decryption failure returns error", func(t *testing.T) {
		action := determinePayloadErrorAction(fmt.Errorf("%w: sig verify failed", errBACAPDecryptionFailed), true, false, false)
		require.Equal(t, payloadActionReturnError, action)
	})

	t.Run("generic error returns error", func(t *testing.T) {
		action := determinePayloadErrorAction(errors.New("something broke"), true, false, false)
		require.Equal(t, payloadActionReturnError, action)
	})

	t.Run("write BoxIDNotFound does not retry", func(t *testing.T) {
		action := determinePayloadErrorAction(boxNotFound, false, false, false)
		require.Equal(t, payloadActionReturnError, action)
	})
}

func TestMapDecryptionErrorToCode(t *testing.T) {
	t.Run("MKEM failure", func(t *testing.T) {
		code := mapDecryptionErrorToCode(errMKEMDecryptionFailed)
		require.Equal(t, thin.ThinClientErrorMKEMDecryptionFailed, code)
	})

	t.Run("BACAP failure", func(t *testing.T) {
		code := mapDecryptionErrorToCode(fmt.Errorf("%w: sig failed", errBACAPDecryptionFailed))
		require.Equal(t, thin.ThinClientErrorBACAPDecryptionFailed, code)
	})

	t.Run("replica error preserves code", func(t *testing.T) {
		code := mapDecryptionErrorToCode(&replicaError{code: pigeonhole.ReplicaErrorTombstone})
		require.Equal(t, pigeonhole.ReplicaErrorTombstone, code)
	})

	t.Run("replica BoxAlreadyExists preserves code", func(t *testing.T) {
		code := mapDecryptionErrorToCode(&replicaError{code: pigeonhole.ReplicaErrorBoxAlreadyExists})
		require.Equal(t, pigeonhole.ReplicaErrorBoxAlreadyExists, code)
	})

	t.Run("generic error maps to internal", func(t *testing.T) {
		code := mapDecryptionErrorToCode(errors.New("unknown"))
		require.Equal(t, thin.ThinClientErrorInternalError, code)
	})
}
