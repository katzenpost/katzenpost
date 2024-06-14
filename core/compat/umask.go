//go:build !windows

package compat

import "syscall"

func Umask(mode int) {
	syscall.Umask(mode)
}
