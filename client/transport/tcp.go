// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"fmt"
	"net"
)

// TcpListenConfig configures a TCP listener.
type TcpListenConfig struct {
	// Address is in host:port form, e.g. "127.0.0.1:64331" or
	// "[::1]:64331". Use "host:0" to request an ephemeral port (the
	// chosen port is recoverable via Listener.Addr after Listen
	// returns).
	Address string `toml:"Address"`

	// Network is optionally one of "tcp", "tcp4", "tcp6". Empty
	// string is equivalent to "tcp" (dual-stack where supported).
	Network string `toml:"Network,omitempty"`
}

// Listen creates a TCP listener bound to c.Address.
func (c *TcpListenConfig) Listen() (Listener, error) {
	network := c.Network
	if network == "" {
		network = "tcp"
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("transport: TcpListenConfig.Network %q is not one of tcp, tcp4, tcp6", network)
	}
	addr, err := net.ResolveTCPAddr(network, c.Address)
	if err != nil {
		return nil, err
	}
	return net.ListenTCP(network, addr)
}
