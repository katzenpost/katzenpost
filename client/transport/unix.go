// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"github.com/katzenpost/katzenpost/core/utils"
)

// UnixListenConfig configures a unix-domain-socket listener.
type UnixListenConfig struct {
	// Address is the path to the unix socket file. The parent
	// directory must exist and be writable by the daemon; a stale
	// socket file left by a crashed daemon is cleared on the next
	// bind, but a socket a live daemon still answers on is left alone.
	Address   string   `toml:"Address"`
	Addresses []string `toml:"Addresses,omitempty"`

	log Logger
}

func (c *UnixListenConfig) Validate() error {
	_, err := c.addresses()
	return err
}

func (c *UnixListenConfig) addresses() ([]string, error) {
	addresses := append([]string{c.Address}, c.Addresses...)
	for i, a := range addresses {
		expanded, err := utils.ExpandUnixSocketPath(a)
		if err != nil {
			return nil, err
		}
		addresses[i] = expanded
	}
	return addresses, nil
}

// Listen creates a unix-domain-socket listener bound to c.Address.
func (c *UnixListenConfig) Listen() (Listener, error) {
	return c.listen(nil)
}
