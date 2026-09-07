// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"errors"
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
	for _, a := range append([]string{c.Address}, c.Addresses...) {
		// "" or "@" would autobind a random abstract socket.
		if a == "" || a == "@" {
			return errors.New("transport: empty unix socket address")
		}
	}
	return nil
}
