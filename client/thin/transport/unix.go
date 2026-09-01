// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import "net"

// UnixDialConfig configures a unix-domain-socket dialer.
type UnixDialConfig struct {
	// Address is the path to the unix socket file the daemon is
	// listening on.
	Address string `toml:"Address"`
}

// Dial opens a unix-domain-socket connection to c.Address.
func (c *UnixDialConfig) Dial() (net.Conn, error) {
	return net.Dial("unix", c.Address)
}
