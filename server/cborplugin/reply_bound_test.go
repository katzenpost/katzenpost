// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
)

const oversizedResponseLength = 64 << 20

type oversizedResponsePlugin struct{}

func (oversizedResponsePlugin) OnCommand(Command) error { return nil }
func (oversizedResponsePlugin) RegisterConsumer(s *Server) {
	go s.Write(&Response{ID: 1, Payload: make([]byte, oversizedResponseLength)})
}

func runOversizedResponseHelper() {
	tmpDir, err := os.MkdirTemp("", "cborplugin_test_helper")
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
	srv := NewServer(logBackend.GetLogger("helper"), socketFile, &RequestFactory{}, oversizedResponsePlugin{})
	fmt.Println(socketFile)
	srv.Accept()
	srv.Wait()
}

func TestClientRefusesResponseLargerThanItsBound(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", "oversized_response")
	logBackend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { logBackend.Close() })
	client := NewClient(logBackend, "test-capability", "test-endpoint", &ResponseFactory{})
	require.NoError(t, client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"}))
	t.Cleanup(func() { client.cmd.Process.Kill() })

	select {
	case cmd := <-client.ReadChan():
		r := cmd.(*Response)
		require.Failf(t, "oversized response decoded", "client decoded and delivered a %d byte response from the plugin", len(r.Payload))
	case <-client.HaltCh():
	case <-time.After(30 * time.Second):
		require.Fail(t, "client neither refused nor delivered the response")
	}
}
