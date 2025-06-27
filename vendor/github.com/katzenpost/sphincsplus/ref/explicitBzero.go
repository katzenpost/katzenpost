// SPDX-FileCopyrightText: (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package sphincsplus

import "runtime"

// ExplicitBzero explicitly clears out the buffer b, by filling it with 0x00
// bytes.
//
//go:noinline
func ExplicitBzero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
