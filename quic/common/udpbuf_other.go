// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package common

import "syscall"

func socketBuffers(syscall.Conn) (receive, send int) {
	return 0, 0
}
