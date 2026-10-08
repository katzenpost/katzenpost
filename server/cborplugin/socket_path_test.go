// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func withoutHostOffer(t *testing.T, behavior string) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", behavior)
	base := ""
	if runtime.GOOS == "darwin" {
		base = "/tmp"
	}
	short, err := os.MkdirTemp(base, "kp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(short) })
	t.Setenv("GO_HELPER_TMPDIR", short)
	dir := filepath.Join(t.TempDir(), strings.Repeat("d", maxSocketPathLen))
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
}

func TestClientFailsAtOnceWithoutASocketPath(t *testing.T) {
	for behavior, line := range map[string]string{"junk_stdout": "plugin starting", "empty_stdout": `""`} {
		t.Run(behavior, func(t *testing.T) {
			client := newTestClient(t)
			withoutHostOffer(t, behavior)
			errCh := make(chan error, 1)
			go func() {
				errCh <- client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"})
			}()
			select {
			case err := <-errCh:
				client.cmd.Process.Kill()
				if err == nil || !strings.Contains(err.Error(), line) {
					t.Fatalf("Start = %v; want an error naming %s", err, line)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Start still waiting on a plugin that printed no socket path")
			}
		})
	}
}

func TestClientLegacyPluginWithoutHostOffer(t *testing.T) {
	client := newEchoClient(t)
	withoutHostOffer(t, "own_tmp")
	if err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { client.cmd.Process.Kill() })
	if client.socketFile == "" || strings.HasPrefix(client.socketFile, os.Getenv("TMPDIR")) {
		t.Fatalf("socket %q is not the plugin's own", client.socketFile)
	}
	requireEcho(t, client)
}
