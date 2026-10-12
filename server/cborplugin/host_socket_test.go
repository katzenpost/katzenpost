// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/katzenpost/katzenpost/core/log"
)

func runHostSocketHelper() {
	socketFile := os.Getenv("KATZENPOST_PLUGIN_SOCKET")
	if os.Getenv("KATZENPOST_PLUGIN_PROTOCOL") != "2" || socketFile == "" {
		fmt.Fprintln(os.Stderr, "host offered no socket")
		os.Exit(3)
	}
	tmpDir, err := os.MkdirTemp("", "cborplugin_host_helper")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logBackend, err := log.New(filepath.Join(tmpDir, "helper.log"), "DEBUG", false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("starting a plugin that takes the host's socket")
	srv := NewServer(logBackend.GetLogger("helper"), socketFile, &RequestFactory{}, &echoServerPlugin{})
	srv.Accept()
	srv.Wait()
}

func TestClientOffersHostSocket(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", "host_socket")

	client := newEchoClient(t)
	if err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { client.cmd.Process.Kill() })
	requireEcho(t, client)
}

func TestClientLegacyPluginWithHostSocketOffered(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", "noisy_stdout")

	client := newEchoClient(t)
	if err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { client.cmd.Process.Kill() })
	requireEcho(t, client)
}
