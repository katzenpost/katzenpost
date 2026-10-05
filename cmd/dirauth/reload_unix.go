// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyReload(ch chan os.Signal) {
	signal.Notify(ch, syscall.SIGUSR1)
}
