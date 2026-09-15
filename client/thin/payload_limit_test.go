// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPayloadTooLargeError pins the new payload-too-large error: its code, its
// human-readable string, and that both sentinel mappers resolve it to the
// ErrPayloadTooLarge sentinel a caller can match with errors.Is.
func TestPayloadTooLargeError(t *testing.T) {
	require.Equal(t, uint8(27), ThinClientErrorPayloadTooLarge)
	require.Equal(t, "Payload too large", ThinClientErrorToString(ThinClientErrorPayloadTooLarge))
	require.ErrorIs(t, thinClientErrorCodeToSentinel(ThinClientErrorPayloadTooLarge), ErrPayloadTooLarge)
	require.ErrorIs(t, errorCodeToSentinel(ThinClientErrorPayloadTooLarge), ErrPayloadTooLarge)
}
