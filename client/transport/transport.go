// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package transport defines the daemon-side transport abstraction used
// by kpclientd to accept thin-client connections. Each concrete
// transport (unix, tcp, and in future ssh / pigeonhole) implements the
// Listener interface and supplies its own config struct carrying its
// own fields. ListenConfig is a discriminated union: exactly one inner
// config must be populated for any given daemon.
package transport

import (
	"errors"
	"net"
)

// Listener is the common interface that all thin-client-facing
// transports must satisfy. It is a subset of net.Listener.
type Listener interface {
	Accept() (net.Conn, error)
	Close() error
	Addr() net.Addr
}

// ListenConfig is the subtable-discriminated listen configuration.
// Exactly one of its pointer fields must be non-nil; zero or two or
// more is a configuration error.
type ListenConfig struct {
	Unix *UnixListenConfig `toml:"Unix,omitempty"`
	Tcp  *TcpListenConfig  `toml:"Tcp,omitempty"`
}

// ErrNoTransport is returned when a ListenConfig has no inner config
// populated.
var ErrNoTransport = errors.New("transport: no listen transport configured")

// ErrMultipleTransports is returned when a ListenConfig has more than
// one inner config populated.
var ErrMultipleTransports = errors.New("transport: exactly one listen transport must be configured")

// Validate checks that exactly one subtable is populated, without
// binding to any socket. Suitable for config-load-time validation.
func (c *ListenConfig) Validate() error {
	if c == nil {
		return ErrNoTransport
	}
	n := 0
	if c.Unix != nil {
		n++
	}
	if c.Tcp != nil {
		n++
	}
	switch n {
	case 0:
		return ErrNoTransport
	case 1:
		return nil
	default:
		return ErrMultipleTransports
	}
}

// Listen resolves the active subtable and returns the corresponding
// Listener. Returns ErrNoTransport if none set, or
// ErrMultipleTransports if more than one is set.
func (c *ListenConfig) Listen() (Listener, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	switch {
	case c.Unix != nil:
		return c.Unix.Listen()
	case c.Tcp != nil:
		return c.Tcp.Listen()
	}
	return nil, ErrNoTransport
}
