// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"os"
	"syscall"
)

type ClientLauncher struct {
	process *os.Process
}

func (l *ClientLauncher) Halt() {
	err := l.process.Signal(syscall.SIGHUP)
	if err != nil {
		panic(err)
	}
	_, err = l.process.Wait()
	if err != nil {
		panic(err)
	}
}

func (l *ClientLauncher) Launch(args ...string) error {
	var procAttr os.ProcAttr
	procAttr.Files = []*os.File{os.Stdin,
		os.Stdout, os.Stderr}
	var err error
	l.process, err = os.StartProcess(args[0], args, &procAttr)
	if err != nil {
		return err
	}
	return nil
}
