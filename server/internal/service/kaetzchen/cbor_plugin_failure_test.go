// SPDX-License-Identifier: AGPL-3.0-only

package kaetzchen

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

func TestCBORPluginUndecodableReplyHelper(t *testing.T) {
	if os.Getenv("GO_WANT_CBOR_PLUGIN_HELPER") != "1" {
		return
	}
	tmpDir, err := os.MkdirTemp("", "kaetzchen_undecodable_helper")
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

func TestCBORPluginWorkerStopsAFailedPlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugins talk over unix domain sockets")
	}
	t.Setenv("GO_WANT_CBOR_PLUGIN_HELPER", "1")

	_, idKey, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)
	logBackend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { logBackend.Close() })
	_, userKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	_, linkKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	goo := getGlue(logBackend, &mockProvider{userName: "alice", userKey: userKey.Public()}, linkKey, idKey)
	goo.s.cfg.ServiceNode.CBORPluginKaetzchen = []*config.CBORPluginKaetzchen{
		{
			Capability:     "undecodable",
			Endpoint:       "undecodable",
			Config:         map[string]interface{}{"test.run": "^TestCBORPluginUndecodableReplyHelper$"},
			Command:        os.Args[0],
			MaxConcurrency: 1,
		},
	}

	k, err := NewCBORPluginWorker(goo)
	require.NoError(t, err)
	t.Cleanup(k.Halt)
	k.Lock()
	require.Len(t, k.clients, 1)
	client := k.clients[0]
	k.Unlock()

	var endpoint [constants.RecipientIDLength]byte
	copy(endpoint[:], "undecodable")
	assert.Eventually(t, func() bool { return !k.IsKaetzchen(endpoint) }, 10*time.Second, 10*time.Millisecond,
		"the plugin stayed registered after its reply failed to decode")

	g := goo.Config().SphinxGeometry
	pkt, err := packet.New(make([]byte, g.PacketLength), g)
	require.NoError(t, err)
	pkt.Recipient = &commands.Recipient{ID: endpoint}
	pkt.DispatchAt = time.Now()
	pkt.Payload = make([]byte, g.ForwardPayloadLength)
	done := make(chan struct{})
	go func() {
		k.processKaetzchen(pkt, client)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		require.Fail(t, "processKaetzchen blocked writing to the failed plugin")
	}
}
