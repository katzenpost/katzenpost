// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCloseDelaySecFixed proves CloseDelaySec is treated as a fixed field:
// a value other than 0 or its fixed default of 10 is rejected with a clear
// error, so an operator is not silently misled into expecting a close grace
// that is never consumed. The accepted default values are not rejected on this
// account (validate fails later on unrelated required fields).
func TestCloseDelaySecFixed(t *testing.T) {
	err := (&Server{CloseDelaySec: 30}).validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "CloseDelaySec")

	if err := (&Server{CloseDelaySec: 10}).validate(); err != nil {
		require.NotContains(t, err.Error(), "CloseDelaySec")
	}
	if err := (&Server{CloseDelaySec: 0}).validate(); err != nil {
		require.NotContains(t, err.Error(), "CloseDelaySec")
	}
}
