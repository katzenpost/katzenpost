// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnectError(t *testing.T) {
	err := newConnectError("dial %s failed", "gateway1")
	require.Contains(t, err.Error(), "connect error")
	require.Contains(t, err.Error(), "dial gateway1 failed")

	var ce *ConnectError
	require.ErrorAs(t, err, &ce)
	require.NotNil(t, ce.Err)
}

func TestPKIError(t *testing.T) {
	err := newPKIError("epoch %d not found", 42)
	require.Contains(t, err.Error(), "PKI error")
	require.Contains(t, err.Error(), "epoch 42 not found")

	var pe *PKIError
	require.ErrorAs(t, err, &pe)
	require.NotNil(t, pe.Err)
}

func TestProtocolError(t *testing.T) {
	err := newProtocolError("bad command %d", 7)
	require.Contains(t, err.Error(), "protocol error")
	require.Contains(t, err.Error(), "bad command 7")

	var pe *ProtocolError
	require.ErrorAs(t, err, &pe)
	require.NotNil(t, pe.Err)
}
