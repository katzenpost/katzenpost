// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDialConfigResolve_Nil(t *testing.T) {
	var cfg *DialConfig
	d, err := cfg.Resolve()
	require.Nil(t, d)
	require.True(t, errors.Is(err, ErrNoTransport))
}

func TestDialConfigResolve_Zero(t *testing.T) {
	cfg := &DialConfig{}
	d, err := cfg.Resolve()
	require.Nil(t, d)
	require.True(t, errors.Is(err, ErrNoTransport))
}

func TestDialConfigResolve_Multiple(t *testing.T) {
	cfg := &DialConfig{
		Unix: &UnixDialConfig{Address: "/tmp/x.sock"},
		Tcp:  &TcpDialConfig{Address: "localhost:0"},
	}
	d, err := cfg.Resolve()
	require.Nil(t, d)
	require.True(t, errors.Is(err, ErrMultipleTransports))
}

func TestDialConfigResolve_UnixDispatch(t *testing.T) {
	cfg := &DialConfig{Unix: &UnixDialConfig{Address: "/tmp/x.sock"}}
	d, err := cfg.Resolve()
	require.NoError(t, err)
	_, ok := d.(*UnixDialConfig)
	require.True(t, ok, "expected *UnixDialConfig, got %T", d)
}

func TestDialConfigResolve_TcpDispatch(t *testing.T) {
	cfg := &DialConfig{Tcp: &TcpDialConfig{Address: "localhost:0"}}
	d, err := cfg.Resolve()
	require.NoError(t, err)
	_, ok := d.(*TcpDialConfig)
	require.True(t, ok, "expected *TcpDialConfig, got %T", d)
}

func TestDialConfigDial_NoTransport(t *testing.T) {
	cfg := &DialConfig{}
	conn, err := cfg.Dial()
	require.Nil(t, conn)
	require.True(t, errors.Is(err, ErrNoTransport))
}
