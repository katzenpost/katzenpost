// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"net/textproto"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/thwack"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/service/kaetzchen"
)

type cfgGlue struct {
	glue.Glue
	cfg *config.Config
}

func (g cfgGlue) Config() *config.Config { return g.cfg }

func TestStopKaetzchenLogsStop(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log")
	logBackend, err := log.New(logFile, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { logBackend.Close() })

	p := &serviceNode{
		glue: cfgGlue{cfg: &config.Config{ServiceNode: &config.ServiceNode{
			CBORPluginKaetzchen: []*config.CBORPluginKaetzchen{{Capability: "echo", Endpoint: "+echo"}},
		}}},
		log:                       logBackend.GetLogger("test"),
		cborPluginKaetzchenWorker: &kaetzchen.CBORPluginWorker{},
	}

	sock := filepath.Join(dir, "s")
	srv, err := thwack.New(&thwack.Config{Net: "unix", Addr: sock, LogModule: "mgmt", NewLoggerFn: logBackend.GetLogger})
	require.NoError(t, err)
	srv.RegisterCommand("STOP_KAETZCHEN", p.onStopKaetzchen)
	require.NoError(t, srv.Start())
	defer srv.Halt()

	conn, err := textproto.Dial("unix", sock)
	require.NoError(t, err)
	_, _, err = conn.ReadCodeLine(int(thwack.StatusServiceReady))
	require.NoError(t, err)
	require.NoError(t, conn.PrintfLine("STOP_KAETZCHEN echo"))
	_, _, err = conn.ReadCodeLine(int(thwack.StatusTransactionFailed))
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	b, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(b), "STOP_KAETZCHEN failed: echo not running")
	require.NotContains(t, string(b), "START_KAETZCHEN")
}
