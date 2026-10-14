// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
)

const commandBound = 4096

func boundedCommandIO(t *testing.T) (*CommandIO, net.Conn) {
	t.Helper()
	lb, err := log.New(filepath.Join(t.TempDir(), "test.log"), "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { lb.Close() })
	c := NewCommandIO(lb.GetLogger("bound"))
	local, remote := net.Pipe()
	c.conn = local
	c.commandBuilder = &ResponseFactory{}
	c.maxCommandLength = commandBound
	c.Go(c.reader)
	t.Cleanup(func() {
		remote.Close()
		local.Close()
		c.Halt()
	})
	return c, remote
}

func encodedResponse(t *testing.T, payload int) []byte {
	t.Helper()
	b, err := cbor.Marshal(&Response{ID: 1, Payload: make([]byte, payload)})
	require.NoError(t, err)
	return b
}

func requireRefused(t *testing.T, c *CommandIO, size int) {
	t.Helper()
	select {
	case <-c.ReadChan():
		require.Failf(t, "oversized command delivered", "a %d byte command passed a %d byte bound", size, commandBound)
	case <-c.HaltCh():
		require.ErrorIs(t, c.err, errCommandTooLong)
	case <-time.After(5 * time.Second):
		require.Fail(t, "reader neither refused nor delivered the command")
	}
}

func TestOneOversizedCommandIsRefused(t *testing.T) {
	c, remote := boundedCommandIO(t)
	big := encodedResponse(t, commandBound)
	go remote.Write(big)
	requireRefused(t, c, len(big))
}

func TestACommandAfterASmallOneIsBoundOnItsOwn(t *testing.T) {
	c, remote := boundedCommandIO(t)
	small, big := encodedResponse(t, 16), encodedResponse(t, commandBound)
	go remote.Write(append(small, big...))
	select {
	case <-c.ReadChan():
	case <-time.After(5 * time.Second):
		require.Fail(t, "the small command was not delivered")
	}
	requireRefused(t, c, len(big))
}
