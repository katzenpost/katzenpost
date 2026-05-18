// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package replica

// availableBytes has no portable syscall.Statfs equivalent on Windows.
// The replica is a RocksDB/CGO Linux service in practice; on Windows
// the filesystem free-space reserve is simply not enforced (false),
// and the MaxStorageBytes quota still applies. Returning false makes
// the watcher skip the reserve check rather than guess.
func availableBytes(path string) (uint64, bool) {
	return 0, false
}
