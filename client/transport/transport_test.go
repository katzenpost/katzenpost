// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListenConfigListen_Nil(t *testing.T) {
	var cfg *ListenConfig
	l, err := cfg.Listen()
	require.Nil(t, l)
	require.True(t, errors.Is(err, ErrNoTransport))
}

func TestListenConfigListen_Zero(t *testing.T) {
	cfg := &ListenConfig{}
	l, err := cfg.Listen()
	require.Nil(t, l)
	require.True(t, errors.Is(err, ErrNoTransport))
}

func TestListenConfigListen_Multiple(t *testing.T) {
	cfg := &ListenConfig{
		Unix: &UnixListenConfig{Address: "/tmp/does-not-matter.sock"},
		Tcp:  &TcpListenConfig{Address: "127.0.0.1:0"},
	}
	l, err := cfg.Listen()
	require.Nil(t, l)
	require.True(t, errors.Is(err, ErrMultipleTransports))
}
