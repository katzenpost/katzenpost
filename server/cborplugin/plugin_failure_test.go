// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func runUndecodableReplyHelper() {
	tmpDir, err := os.MkdirTemp("", "cborplugin_undecodable_helper")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	socketFile := filepath.Join(tmpDir, "helper.socket")
	listener, err := net.Listen("unix", socketFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(socketFile)
	conn, err := listener.Accept()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := conn.Write([]byte{0xff, 0xff, 0xff, 0xff}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	time.Sleep(time.Hour)
}

func TestClientStopsWhenThePluginReplyFailsToDecode(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", "undecodable_reply")
	client := newTestClient(t)
	require.NoError(t, client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"}))
	t.Cleanup(func() { client.cmd.Process.Kill() })

	select {
	case <-client.HaltCh():
	case <-time.After(10 * time.Second):
		require.Fail(t, "client did not stop after the plugin's reply failed to decode")
	}
	halted := make(chan struct{})
	go func() {
		client.Halt()
		close(halted)
	}()
	select {
	case <-halted:
	case <-time.After(10 * time.Second):
		require.Fail(t, "client Halt did not return after the plugin failed")
	}
}
