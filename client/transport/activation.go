// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

const listenFDsStart = 3

func inheritedListeners() ([]Listener, error) {
	pid, fds := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	if pid != strconv.Itoa(os.Getpid()) {
		return nil, nil
	}
	n, err := strconv.Atoi(fds)
	if err != nil || n < 0 {
		return nil, fmt.Errorf("transport: invalid LISTEN_FDS %q", fds)
	}
	listeners := make([]Listener, 0, n)
	for fd := listenFDsStart; fd < listenFDsStart+n; fd++ {
		f := os.NewFile(uintptr(fd), "LISTEN_FDS")
		l, err := net.FileListener(f)
		f.Close()
		if err != nil {
			closeListeners(listeners)
			return nil, fmt.Errorf("transport: inherited fd %d: %w", fd, err)
		}
		listeners = append(listeners, l)
	}
	return listeners, nil
}

func refuseInherited(inherited []Listener, unmatched net.Addr) error {
	closeListeners(inherited)
	return fmt.Errorf("transport: inherited socket %s matches no configured [Listen.Unix] address", unmatched)
}
