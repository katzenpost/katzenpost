// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/katzenpost/katzenpost/core/log"
)

func writeFlood(f *os.File) {
	f.Write([]byte(strings.Repeat("x", 8<<20) + "\n"))
	line := []byte(strings.Repeat("y", 4095) + "\n")
	for i := 0; i < 4096; i++ {
		f.Write(line)
	}
}

func floodedLogSize(t *testing.T, behavior string) int64 {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", behavior)
	logFile := filepath.Join(t.TempDir(), "test.log")
	logBackend, err := log.New(logFile, "DEBUG", false)
	if err != nil {
		t.Fatalf("log.New: %v", err)
	}
	t.Cleanup(func() { logBackend.Close() })
	client := NewClient(logBackend, "test-capability", "test-endpoint", &ResponseFactory{})
	if err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { client.cmd.Process.Kill() })
	requireEcho(t, client)
	fi, err := os.Stat(logFile)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func TestClientBoundsLoggedPluginStdout(t *testing.T) {
	if size := floodedLogSize(t, "stdout_flood"); size > 8<<20 {
		t.Fatalf("log grew to %d bytes from a 24 MiB stdout flood", size)
	}
}

func TestClientBoundsLoggedPluginStderr(t *testing.T) {
	if size := floodedLogSize(t, "stderr_flood"); size > 8<<20 {
		t.Fatalf("log grew to %d bytes from a 24 MiB stderr flood", size)
	}
}
