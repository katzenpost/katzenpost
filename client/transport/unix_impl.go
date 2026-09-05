// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !wasm

package transport

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// Listen creates a unix-domain-socket listener bound to c.Address.
func (c *UnixListenConfig) Listen() (Listener, error) {
	return listenUnix(c.Address)
}

// listenUnix binds a single unix socket, clearing a stale socket file
// left by a crashed daemon before giving up.
func listenUnix(address string) (Listener, error) {
	addr, err := net.ResolveUnixAddr("unix", address)
	if err != nil {
		return nil, err
	}
	l, err := net.ListenUnix("unix", addr)
	if err == nil {
		return l, nil
	}
	if !errors.Is(err, syscall.EADDRINUSE) || !staleUnixSocket(address) {
		return nil, err
	}
	if rmErr := os.Remove(address); rmErr != nil {
		return nil, err
	}
	return net.ListenUnix("unix", addr)
}

// staleUnixSocket reports whether address is a filesystem socket that no
// live daemon still answers on. An abstract socket (@ prefix) never
// outlives its owner, so EADDRINUSE there always means a live owner.
func staleUnixSocket(address string) bool {
	if strings.HasPrefix(address, "@") {
		return false
	}
	fi, err := os.Stat(address)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return false
	}
	conn, err := net.DialTimeout("unix", address, 100*time.Millisecond)
	if err == nil {
		conn.Close()
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}
