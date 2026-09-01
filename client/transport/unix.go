// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"errors"
	"os"
)

// UnixListenConfig configures a unix-domain-socket listener.
type UnixListenConfig struct {
	// Address is the path to the unix socket file. The parent
	// directory must exist and be writable by the daemon; any stale
	// socket file at the path is the operator's responsibility.
	Address string `toml:"Address"`
	// Addresses are additional sockets bound alongside Address.
	Addresses []string `toml:"Addresses,omitempty"`

	log Logger
}

func (c *UnixListenConfig) Validate() error {
	for _, a := range append([]string{c.Address}, c.Addresses...) {
		// "" or "@" would autobind a random abstract socket.
		if name := os.ExpandEnv(a); name == "" || name == "@" {
			return errors.New("transport: empty unix socket address")
		}
	}
	return nil
}
