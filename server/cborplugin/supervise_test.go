// SPDX-License-Identifier: AGPL-3.0-only

package cborplugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
)

func TestSuperviseLogsNoNilFailure(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.log")
	logBackend, err := log.New(f, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { logBackend.Close() })
	c := &Client{socket: NewCommandIO(logBackend.GetLogger("socket")), log: logBackend.GetLogger("client"), capability: "quiet"}
	c.socket.Halt()
	c.supervise()
	b, err := os.ReadFile(f)
	require.NoError(t, err)
	require.NotContains(t, string(b), "<nil>")
	select {
	case <-c.HaltCh():
	default:
		require.Fail(t, "client not stopped after its socket halted")
	}
}
