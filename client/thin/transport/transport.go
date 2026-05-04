// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package transport defines the thin-client-side transport abstraction
// used by the Go thin-client to dial the kpclientd daemon. Each
// concrete transport (unix, tcp, and in future ssh / pipe / pigeonhole)
// implements the Dialer interface and supplies its own config struct
// carrying its own fields. DialConfig is a discriminated union:
// exactly one inner config must be populated for any given thin-client.
package transport

import (
	"errors"
	"net"
)

// Dialer is the common interface that all thin-client-side transports
// must satisfy. Dial returns a net.Conn on which the thin-client
// framing layer (4-byte length prefix + CBOR) is spoken.
type Dialer interface {
	Dial() (net.Conn, error)
}

// DialConfig is the subtable-discriminated dial configuration.
// Exactly one of its pointer fields must be non-nil; zero or two or
// more is a configuration error.
type DialConfig struct {
	Unix *UnixDialConfig `toml:"Unix,omitempty"`
	Tcp  *TcpDialConfig  `toml:"Tcp,omitempty"`
}

// ErrNoTransport is returned when a DialConfig has no inner config
// populated.
var ErrNoTransport = errors.New("transport: no dial transport configured")

// ErrMultipleTransports is returned when a DialConfig has more than
// one inner config populated.
var ErrMultipleTransports = errors.New("transport: exactly one dial transport must be configured")

// Validate checks that exactly one subtable is populated, without
// attempting any connection. Suitable for config-load-time validation.
func (c *DialConfig) Validate() error {
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

// Resolve returns the active inner dialer. Returns ErrNoTransport if
// none set, or ErrMultipleTransports if more than one is set.
func (c *DialConfig) Resolve() (Dialer, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	switch {
	case c.Unix != nil:
		return c.Unix, nil
	case c.Tcp != nil:
		return c.Tcp, nil
	}
	return nil, ErrNoTransport
}

// Dial is a convenience wrapper: Resolve + Dial in one call.
func (c *DialConfig) Dial() (net.Conn, error) {
	d, err := c.Resolve()
	if err != nil {
		return nil, err
	}
	return d.Dial()
}
