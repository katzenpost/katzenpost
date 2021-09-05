// monotime_linux.go - Linux Monotonic clock.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// +build !go1.9

package monotime

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	vdsoClockGettime uintptr
	useVDSO          = false
)

func nowImpl() time.Duration {
	const clockMonotonicRaw = 4

	var ts syscall.Timespec
	res := uintptr(unsafe.Pointer(&ts))

	if useVDSO {
		vdsoClockGettimeTrampoline(clockMonotonicRaw, res, vdsoClockGettime)
	} else {
		_, _, e1 := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockMonotonicRaw, res, 0)
		if e1 != 0 {
			panic("monotime: clock_gettime(CLOCK_MONOTONIC_RAW, &ts): " + e1.Error())
		}
	}

	return time.Duration(ts.Nano()) * time.Nanosecond
}

func init() {
	if err := initArchDep(); err == nil {
		useVDSO = true
	}
}
