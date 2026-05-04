// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"fmt"
	"net"
)

// TcpDialConfig configures a TCP dialer.
type TcpDialConfig struct {
	// Address is in host:port form, e.g. "127.0.0.1:64331" or
	// "[::1]:64331".
	Address string `toml:"Address"`

	// Network is optionally one of "tcp", "tcp4", "tcp6". Empty
	// string is equivalent to "tcp" (dual-stack where supported).
	Network string `toml:"Network,omitempty"`
}

// Dial opens a TCP connection to c.Address.
func (c *TcpDialConfig) Dial() (net.Conn, error) {
	network := c.Network
	if network == "" {
		network = "tcp"
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("transport: TcpDialConfig.Network %q is not one of tcp, tcp4, tcp6", network)
	}
	return net.Dial(network, c.Address)
}
