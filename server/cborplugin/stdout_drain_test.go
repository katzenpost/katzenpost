// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/core/log"
)

type echoServerPlugin struct {
	server *Server
}

func (e *echoServerPlugin) RegisterConsumer(s *Server) { e.server = s }

func (e *echoServerPlugin) OnCommand(cmd Command) error {
	req := cmd.(*Request)
	e.server.Write(&Response{ID: req.ID, Payload: req.Payload})
	return nil
}

func runEchoHelper(announce func(socketFile string)) {
	tmpDir, err := os.MkdirTemp("", "cborplugin_echo_helper")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logBackend, err := log.New(filepath.Join(tmpDir, "helper.log"), "DEBUG", false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	socketFile := filepath.Join(tmpDir, "helper.socket")
	srv := NewServer(logBackend.GetLogger("helper"), socketFile, &RequestFactory{}, &echoServerPlugin{})
	announce(socketFile)
	srv.Accept()
	srv.Wait()
}

func requireEcho(t *testing.T, client *Client) {
	t.Helper()
	select {
	case client.WriteChan() <- &Request{ID: 7, Payload: []byte("ping")}:
	case <-time.After(5 * time.Second):
		t.Fatal("plugin did not take the request")
	}
	select {
	case cmd := <-client.ReadChan():
		resp, ok := cmd.(*Response)
		if !ok || resp.ID != 7 || string(resp.Payload) != "ping" {
			t.Fatalf("unexpected reply: %#v", cmd)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("plugin did not answer")
	}
}

func newEchoClient(t *testing.T) *Client {
	t.Helper()
	logBackend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "DEBUG", false)
	if err != nil {
		t.Fatalf("log.New: %v", err)
	}
	t.Cleanup(func() { logBackend.Close() })
	return NewClient(logBackend, "test-capability", "test-endpoint", &ResponseFactory{})
}

func TestClientDrainsPluginStdout(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", "noisy_stdout")

	client := newEchoClient(t)
	if err := client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { client.cmd.Process.Kill() })
	requireEcho(t, client)
}
