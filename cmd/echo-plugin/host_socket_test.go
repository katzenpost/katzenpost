// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/server/cborplugin"
)

func isSocketFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

func TestEchoPluginHelper(t *testing.T) {
	if os.Getenv("GO_WANT_PLUGIN_HELPER") != "1" {
		return
	}
	runEcho(echoConfig{logDir: os.Getenv("PLUGIN_LOG_DIR"), logLevel: "DEBUG"})
	os.Exit(0)
}

func TestPluginTakesHostSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "host.socket")
	t.Setenv(cborplugin.PluginProtocolEnv, cborplugin.PluginProtocol)
	t.Setenv(cborplugin.PluginSocketEnv, socket)
	logDir := t.TempDir()
	go runEcho(echoConfig{logDir: logDir, logLevel: "DEBUG"})
	deadline := time.Now().Add(10 * time.Second)
	for !isSocketFile(socket) {
		if time.Now().After(deadline) {
			t.Fatalf("plugin did not listen on the host's socket %s", socket)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPluginPrintsOwnSocketWithoutHost(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestEchoPluginHelper$")
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, cborplugin.PluginProtocolEnv+"=") && !strings.HasPrefix(kv, cborplugin.PluginSocketEnv+"=") {
			env = append(env, kv)
		}
	}
	cmd.Env = append(env, "GO_WANT_PLUGIN_HELPER=1", "PLUGIN_LOG_DIR="+t.TempDir())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("plugin printed no socket path: %v", err)
	}
	path := strings.TrimSpace(line)
	deadline := time.Now().Add(10 * time.Second)
	for !isSocketFile(path) {
		if time.Now().After(deadline) {
			t.Fatalf("plugin printed %q, which is not its socket", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
