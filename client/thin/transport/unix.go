// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"net"

	"github.com/katzenpost/katzenpost/core/utils"
)

// UnixDialConfig configures a unix-domain-socket dialer.
type UnixDialConfig struct {
	// Address is the path to the unix socket file the daemon is
	// listening on.
	Address string `toml:"Address"`
}

// Dial opens a unix-domain-socket connection to c.Address.
func (c *UnixDialConfig) Dial() (net.Conn, error) {
	address, err := utils.ExpandUnixSocketPath(c.Address)
	if err != nil {
		return nil, err
	}
	return net.Dial("unix", address)
}

func (c *UnixDialConfig) Validate() error {
	_, err := utils.ExpandUnixSocketPath(c.Address)
	return err
}
