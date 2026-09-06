// client_test.go - tests for cbor plugin client startup failure handling
// Copyright (C) 2026  David Stainton.
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

package cborplugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/core/log"
)

// TestHelperProcess is not a real test. The tests below re-exec the test
// binary itself (via os.Args[0]) as a fake plugin subprocess, following the
// pattern used by the standard library's own os/exec tests. It must return
// immediately unless GO_WANT_HELPER_PROCESS is set, so that a normal test
// run of this package treats it as an ordinary no-op test.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	switch os.Getenv("GO_HELPER_BEHAVIOR") {
	case "exit_silent":
		os.Exit(1)
	case "exit_with_stderr":
		fmt.Fprintln(os.Stderr, "simulated plugin startup failure: permission denied")
		os.Exit(1)
	case "handshake_ok":
		runHandshakeOKHelper()
	}
	os.Exit(2)
}

type fakeServerPlugin struct{}

func (fakeServerPlugin) OnCommand(Command) error  { return nil }
func (fakeServerPlugin) RegisterConsumer(*Server) {}

func runHandshakeOKHelper() {
	tmpDir, err := os.MkdirTemp("", "cborplugin_test_helper")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// core/log's disable=true discard path panics on any write it actually
	// receives (a separate, pre-existing bug) - log to a real file instead.
	logBackend, err := log.New(filepath.Join(tmpDir, "helper.log"), "DEBUG", false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	socketFile := filepath.Join(tmpDir, "helper.socket")
	srv := NewServer(logBackend.GetLogger("helper"), socketFile, &RequestFactory{}, fakeServerPlugin{})
	fmt.Println(socketFile)
	srv.Accept()
	srv.Wait()
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	// core/log's disable=true discard path (newDiscardCloser) panics on any
	// non-empty write (nil embedded io.WriteCloser) — a separate, pre-existing
	// bug. Route to a real temp file instead of exercising it here.
	logBackend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "DEBUG", false)
	if err != nil {
		t.Fatalf("log.New: %v", err)
	}
	return NewClient(logBackend, "test-capability", "test-endpoint", &RequestFactory{})
}

const helperTimeoutBudget = 5 * time.Second

func TestClientStartPluginExitsSilently(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", "exit_silent")

	client := newTestClient(t)
	start := time.Now()
	err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Start to return an error")
	}
	if elapsed > helperTimeoutBudget {
		t.Fatalf("Start took %v to fail; expected well under the old ~40s retry budget", elapsed)
	}
	if !strings.Contains(err.Error(), "exited before providing a socket path") {
		t.Fatalf("error does not mention the early exit: %v", err)
	}
}

func TestClientStartPluginExitsWithStderr(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", "exit_with_stderr")

	client := newTestClient(t)
	start := time.Now()
	err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Start to return an error")
	}
	if elapsed > helperTimeoutBudget {
		t.Fatalf("Start took %v to fail; expected well under the old ~40s retry budget", elapsed)
	}
	if !strings.Contains(err.Error(), "simulated plugin startup failure: permission denied") {
		t.Fatalf("error does not include captured stderr: %v", err)
	}
}

func TestClientStartHandshakeOK(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", "handshake_ok")

	client := newTestClient(t)
	err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"})
	if err != nil {
		t.Fatalf("expected Start to succeed, got: %v", err)
	}
	// Kill the helper subprocess directly rather than calling client.Halt():
	// logPluginStderr already calls Halt() itself once stderr closes, from
	// within its own Go()-registered goroutine, which can never observe its
	// own completion; a second concurrent Halt() call here would join that
	// same wait and hang the test. Killing the process is enough to make
	// stderr close, which triggers that chain; reaper() then owns the
	// resulting Wait() call, so we must not also call it here ourselves.
	t.Cleanup(func() {
		client.cmd.Process.Kill()
	})
}
