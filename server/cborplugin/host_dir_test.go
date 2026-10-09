// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireNoHostOffer(t *testing.T, env []string) {
	t.Helper()
	for _, kv := range env {
		if strings.HasPrefix(kv, PluginSocketEnv+"=") || strings.HasPrefix(kv, PluginProtocolEnv+"=") {
			t.Fatalf("host offered %q", kv)
		}
	}
}

func TestOfferHostSocketSkipsOverlongPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), strings.Repeat("d", maxSocketPathLen))
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	c := &Client{cmd: exec.Command("true")}
	socket, err := c.offerHostSocket()
	if err != nil || socket != "" {
		t.Fatalf("offerHostSocket = %q, %v; want no offer", socket, err)
	}
	if !strings.HasPrefix(c.hostDir, dir) {
		t.Fatalf("hostDir %q not under TMPDIR", c.hostDir)
	}
	requireNoHostOffer(t, c.cmd.Env)
}

func TestOfferHostSocketFailsWithoutTempDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("TMPDIR", missing)
	t.Setenv("TMP", missing)
	c := &Client{cmd: exec.Command("true")}
	if socket, err := c.offerHostSocket(); err == nil {
		t.Fatalf("offerHostSocket = %q, nil; want an error", socket)
	}
	requireNoHostOffer(t, c.cmd.Env)
}

func TestClientStartFailsWithoutTempDir(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", "handshake_ok")
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("TMPDIR", missing)
	t.Setenv("TMP", missing)
	client := newTestClient(t)
	if err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"}); err == nil {
		client.cmd.Process.Kill()
		t.Fatal("Start succeeded without a temp dir")
	}
	if client.cmd.Process != nil {
		t.Fatal("plugin was started")
	}
}

func TestClientRemovesHostDirOnEarlyExit(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", "exit_silent")
	client := newTestClient(t)
	if err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"}); err == nil {
		t.Fatal("Start succeeded")
	}
	if client.hostDir == "" {
		t.Fatal("no host dir was made")
	}
	if _, err := os.Stat(client.hostDir); !os.IsNotExist(err) {
		t.Fatalf("host dir %q left behind: %v", client.hostDir, err)
	}
}

func TestClientRemovesHostDirWhenPluginExits(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", "host_socket")
	client := newEchoClient(t)
	if err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := os.Stat(client.hostDir); err != nil {
		t.Fatalf("host dir missing while the plugin runs: %v", err)
	}
	client.cmd.Process.Kill()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(client.hostDir); os.IsNotExist(err) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("host dir %q left behind after the plugin exited", client.hostDir)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
