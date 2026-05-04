// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import "net"

// UnixListenConfig configures a unix-domain-socket listener.
type UnixListenConfig struct {
	// Address is the path to the unix socket file. The parent
	// directory must exist and be writable by the daemon; any stale
	// socket file at the path is the operator's responsibility.
	Address string `toml:"Address"`
}

// Listen creates a unix-domain-socket listener bound to c.Address.
func (c *UnixListenConfig) Listen() (Listener, error) {
	addr, err := net.ResolveUnixAddr("unix", c.Address)
	if err != nil {
		return nil, err
	}
	return net.ListenUnix("unix", addr)
}
