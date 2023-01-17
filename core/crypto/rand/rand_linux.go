// rand_linux.go - Linux getentropy() based on getrandom().
// Copyright (C) 2016  Yawning Angel.
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

package rand

import (
	"bytes"
	"crypto/rand"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

var getrandomTrap uintptr

// Mimic OpenBSD's getentropy semantics.
//
// This means:
//  * BLOCK like god intended it, if the system entropy source isn't
//    initialized.
//  * Don't ever return truncated reads, even if signal handlers are involved.
//  * Reject reads over 256 bytes long.
func getentropy(b []byte) error {
	if len(b) <= 256 {
		var buf, buflen, flags uintptr
		buf = uintptr(unsafe.Pointer(&b[0]))
		buflen = uintptr(len(b))
		flags = 0

		r1, _, err := syscall.Syscall(getrandomTrap, buf, buflen, flags)
		if err != 0 {
			return err
		}
		if r1 == buflen {
			return nil
		}
	}

	return syscall.EIO
}

func waitOnUrandomSanity() error {
	for {
		// Use the /proc interface to query the entropy estimate.
		buf, err := os.ReadFile("/proc/sys/kernel/random/entropy_avail")
		if err != nil {
			return err
		}
		entropy, err := strconv.ParseInt(string(bytes.TrimSpace(buf)), 10, 0)
		if err != nil {
			return err
		}

		// The kernel considers an entropy pool initialized if it ever
		// exceeds 128 bits of entropy.  Since we can't tell if this has
		// happened in the past for the nonblocking pool, wait till we
		// see the threshold has been exceeded.
		if entropy > 128 {
			return nil
		}

		// Don't busy wait.
		time.Sleep(1 * time.Second)
	}
}

// Detect support for getrandom(2).
func initGetrandom() error {
	switch runtime.GOARCH {
	case "amd64":
		getrandomTrap = 318
	case "386":
		getrandomTrap = 355
	case "arm":
		getrandomTrap = 384
	case "arm64":
		getrandomTrap = 278
	default:
		// Your platform is the most special snowflake of them all.
		return syscall.ENOSYS
	}

	var err error
	var tmp [1]byte
	for {
		err = getentropy(tmp[:])
		switch err {
		case nil:
			return nil
		case syscall.EINTR:
			// Interrupted by a signal handler while waiting for the entropy
			// pool to initialize, try again.
		default:
			return err
		}
	}
}

func init() {
	if err := initGetrandom(); err == nil {
		// getrandom(2) appears to work, and is initialized.
		usingImprovedSyscallEntropy = true
		Reader = &nonShitRandReader{getentropy}
	} else {
		// The system is likely older than Linux 3.17, which while
		// prehistoric, is still used on things.
		//
		// Wait till the system entropy pool is sufficiently initialized,
		// such that crypto/rand.Reader returns quality results.
		if err = waitOnUrandomSanity(); err != nil {
			panic("rand: failed to get a sane /dev/urandom: " + err.Error())
		}
		Reader = rand.Reader
	}
	initWhitening()
}
