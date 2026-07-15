// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !thinclient

package transport

import "net"

// Listen creates a unix-domain-socket listener bound to c.Address.
func (c *UnixListenConfig) Listen() (Listener, error) {
	addr, err := net.ResolveUnixAddr("unix", c.Address)
	if err != nil {
		return nil, err
	}
	return net.ListenUnix("unix", addr)
}
