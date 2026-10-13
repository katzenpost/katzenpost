// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package common

import "syscall"

func socketBuffers(c syscall.Conn) (receive, send int) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0
	}
	raw.Control(func(fd uintptr) {
		receive, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		send, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	})
	return receive, send
}
