//go:build !windows

package main

import "syscall"

func Umask(mode int) {
	syscall.Umask(mode)
}
