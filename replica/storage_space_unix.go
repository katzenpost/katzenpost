// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package replica

import "syscall"

// availableBytes returns the number of bytes available to a
// non-privileged process on the filesystem backing path, and true on
// success. It is used for the storage free-space reserve check.
func availableBytes(path string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, false
	}
	// Bavail is the count of blocks available to non-root; Bsize is
	// the fundamental block size. Their product is the space a normal
	// process may still consume.
	return uint64(st.Bavail) * uint64(st.Bsize), true
}
