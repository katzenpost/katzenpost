// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

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

func TestAddressesFromURLs(t *testing.T) {
	t.Run("tcp4 address", func(t *testing.T) {
		result := addressesFromURLs([]string{"tcp4://127.0.0.1:30001"})
		require.Len(t, result, 1)
		require.Contains(t, result, "tcp4")
		require.Len(t, result["tcp4"], 1)
	})

	t.Run("multiple transports", func(t *testing.T) {
		result := addressesFromURLs([]string{
			"tcp4://127.0.0.1:30001",
			"tcp://10.0.0.1:30002",
			"quic://10.0.0.1:30003",
		})
		require.Len(t, result, 3)
		require.Contains(t, result, "tcp4")
		require.Contains(t, result, "tcp")
		require.Contains(t, result, "quic")
	})

	t.Run("multiple same transport", func(t *testing.T) {
		result := addressesFromURLs([]string{
			"tcp4://127.0.0.1:30001",
			"tcp4://127.0.0.1:30002",
		})
		require.Len(t, result["tcp4"], 2)
	})

	t.Run("unknown scheme ignored", func(t *testing.T) {
		result := addressesFromURLs([]string{"ftp://example.com/file"})
		require.Len(t, result, 0)
	})

	t.Run("invalid URL ignored", func(t *testing.T) {
		result := addressesFromURLs([]string{"://bad"})
		require.Len(t, result, 0)
	})

	t.Run("empty input", func(t *testing.T) {
		result := addressesFromURLs(nil)
		require.Len(t, result, 0)
	})

	t.Run("onion transport", func(t *testing.T) {
		result := addressesFromURLs([]string{"onion://abcdef.onion:80"})
		require.Len(t, result, 1)
		require.Contains(t, result, "onion")
	})

	t.Run("mixed valid and invalid", func(t *testing.T) {
		result := addressesFromURLs([]string{
			"tcp4://127.0.0.1:30001",
			"ftp://bad.com",
			"://alsabad",
			"tcp://10.0.0.1:30002",
		})
		require.Len(t, result, 2)
	})
}
