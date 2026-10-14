// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	clienttransport "github.com/katzenpost/katzenpost/client/transport"
)

func TestLoadFileRejectsUnsetSocketEnv(t *testing.T) {
	t.Setenv("KP_TEST_UNSET", "")
	os.Unsetenv("KP_TEST_UNSET")
	cfg, err := LoadFile(writeTempToml(t, "[Dial]\n  [Dial.Unix]\n    Address = \"$KP_TEST_UNSET/katzenpost/kpclientd.sock\"\n"))
	require.ErrorIs(t, err, ErrInvalidThinConfig)
	require.ErrorContains(t, err, "KP_TEST_UNSET is unset or empty")
	require.Nil(t, cfg)
}

func TestDaemonAndThinClientMeetAtExpandedPath(t *testing.T) {
	dir, err := os.MkdirTemp("", "ks")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "katzenpost"), 0700))
	cfg := &config.Config{Listen: &clienttransport.ListenConfig{Unix: &clienttransport.UnixListenConfig{Address: "$XDG_RUNTIME_DIR/katzenpost/kpclientd.sock"}}}

	listener, err := cfg.Listen.Listen()
	require.NoError(t, err)
	defer listener.Close()
	conn, err := FromConfig(cfg).Dial.Dial()
	require.NoError(t, err)
	defer conn.Close()
	accepted, err := listener.Accept()
	require.NoError(t, err)
	require.NoError(t, accepted.Close())
}
