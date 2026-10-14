// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
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
	client := NewClient(logBackend, "test-capability", "test-endpoint", &ResponseFactory{}, 1<<20)
	require.NoError(t, client.Start(os.Args[0], []string{"-test.run=TestHelperProcess"}))
	t.Cleanup(func() { client.cmd.Process.Kill() })

	select {
	case cmd := <-client.ReadChan():
		r := cmd.(*Response)
		require.Failf(t, "oversized response decoded", "client decoded and delivered a %d byte response from the plugin", len(r.Payload))
	case <-client.socket.HaltCh():
	case <-time.After(30 * time.Second):
		require.Fail(t, "client neither refused nor delivered the response")
	}
}

func TestBoundedReaderPassesBackToBackCommandsAtTheBound(t *testing.T) {
	const bound = 4096
	logBackend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { logBackend.Close() })
	local, remote := net.Pipe()
	defer remote.Close()
	c := NewCommandIO(logBackend.GetLogger("test"))
	c.conn = local
	c.commandBuilder = &ResponseFactory{}
	c.maxCommandLength = bound
	c.Go(c.reader)
	defer local.Close()

	encode := func(r *Response) []byte {
		b, err := cbor.Marshal(r)
		require.NoError(t, err)
		return b
	}
	r := &Response{ID: 1}
	for len(encode(r)) < bound {
		r.Payload = append(r.Payload, 0)
	}
	b := encode(r)
	require.Equal(t, bound, len(b))
	stream := make([]byte, 0, 8*bound)
	for i := 0; i < 8; i++ {
		stream = append(stream, b...)
	}
	go remote.Write(stream)
	for i := 0; i < 8; i++ {
		select {
		case cmd := <-c.ReadChan():
			require.Len(t, cmd.(*Response).Payload, len(r.Payload))
		case <-c.HaltCh():
			require.Failf(t, "reader halted", "command %d of length %d refused at bound %d", i, len(b), bound)
		}
	}
	go remote.Write(encode(&Response{ID: 2, Payload: make([]byte, 4*bound)}))
	select {
	case <-c.ReadChan():
		require.Fail(t, "command over the bound delivered")
	case <-c.HaltCh():
	case <-time.After(10 * time.Second):
		require.Fail(t, "reader neither refused nor delivered")
	}
}

func TestBoundedReaderReportsEOFAfterAReplyAtTheBound(t *testing.T) {
	const bound = 4096
	logBackend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { logBackend.Close() })
	r := &Response{ID: 1}
	for b, _ := cbor.Marshal(r); len(b) < bound; b, _ = cbor.Marshal(r) {
		r.Payload = append(r.Payload, 0)
	}
	atBound, err := cbor.Marshal(r)
	require.NoError(t, err)
	require.Len(t, atBound, bound)
	small, err := cbor.Marshal(&Response{ID: 2})
	require.NoError(t, err)
	cases := []struct {
		name   string
		stream []byte
		want   int
	}{
		{"alone", atBound, 1},
		{"after a read-ahead", append(append([]byte{}, small...), atBound...), 2},
	}
	for _, tc := range cases {
		local, remote := net.Pipe()
		c := NewCommandIO(logBackend.GetLogger("test"))
		c.conn = local
		c.commandBuilder = &ResponseFactory{}
		c.maxCommandLength = bound
		c.Go(c.reader)
		go func() {
			remote.Write(tc.stream)
			remote.Close()
		}()
		delivered := 0
	read:
		for {
			select {
			case <-c.ReadChan():
				delivered++
			case <-c.HaltCh():
				break read
			case <-time.After(10 * time.Second):
				require.Fail(t, "reader neither delivered nor halted", tc.name)
			}
		}
		require.Equal(t, tc.want, delivered, tc.name)
		require.ErrorIs(t, c.err, io.EOF, tc.name)
		local.Close()
	}
}
