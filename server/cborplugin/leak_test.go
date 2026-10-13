// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package cborplugin

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLeakHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_LEAK_HELPER") != "1" {
		return
	}
	switch os.Getenv("GO_LEAK_BEHAVIOR") {
	case "echo":
		runEchoHelper(func(socketFile string) { fmt.Println(socketFile) })
	case "ignore_term":
		signal.Ignore(syscall.SIGTERM)
		runEchoHelper(func(socketFile string) { fmt.Println(socketFile) })
	case "bound_not_listening":
		dir, err := os.MkdirTemp("", "leak")
		if err != nil {
			os.Exit(1)
		}
		socketFile := filepath.Join(dir, "h.socket")
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketFile, Net: "unix"})
		if err != nil {
			os.Exit(1)
		}
		l.SetUnlinkOnClose(false)
		l.Close()
		fmt.Println(socketFile)
		time.Sleep(2 * time.Minute)
	}
	os.Exit(2)
}

func startLeakHelper(t *testing.T, behavior string) (*Client, error) {
	t.Helper()
	t.Setenv("GO_WANT_LEAK_HELPER", "1")
	t.Setenv("GO_LEAK_BEHAVIOR", behavior)
	c := newTestClient(t)
	return c, c.Start(os.Args[0], []string{"-test.run=TestLeakHelperProcess"})
}

func alive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func waitDead(t *testing.T, pid int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("plugin still alive after %v", within)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestHaltReturnsAfterPluginExit(t *testing.T) {
	c, err := startLeakHelper(t, "echo")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	pid := c.cmd.Process.Pid
	c.cmd.Process.Kill()
	waitDead(t, pid, 10*time.Second)
	done := make(chan struct{})
	go func() { c.Halt(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Halt blocked 5s after the plugin was reaped")
	}
}
