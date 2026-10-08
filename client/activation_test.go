// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package client

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/client/transport"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

const activationChild = "KP_TEST_ACTIVATION_CHILD"

func TestThinClientHandshakeOverInheritedSocket(t *testing.T) {
	if os.Getenv(activationChild) == "" {
		dir, err := os.MkdirTemp("", "ks")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(dir) })
		path := filepath.Join(dir, "kpclientd.sock")
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		require.NoError(t, err)
		defer l.Close()
		f, err := l.File()
		require.NoError(t, err)
		defer f.Close()
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
		cmd.Env = append(os.Environ(), activationChild+"=1", "KP_TEST_SOCK="+path, "LISTEN_FDS=1")
		cmd.ExtraFiles = []*os.File{f}
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		return
	}
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	path := os.Getenv("KP_TEST_SOCK")
	before, err := os.Stat(path)
	require.NoError(t, err)

	cfg, err := config.LoadFile(testClientTOML)
	require.NoError(t, err)
	cfg.Listen = &transport.ListenConfig{Unix: &transport.UnixListenConfig{Address: path}}
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{cfg: cfg, logbackend: logBackend, log: logBackend.GetLogger("client")}
	epoch, _, _ := epochtime.Now()
	blob, err := cbor.Marshal(&cpki.Document{Epoch: epoch})
	require.NoError(t, err)
	c.pki = &pki{c: c, log: logBackend.GetLogger("pki"), docs: sync.Map{}}
	c.pki.docs.Store(epoch, &CachedDoc{Doc: &cpki.Document{Epoch: epoch}, Blob: blob})

	l, err := NewListener(c, &Rates{}, make(chan *Request, 10), logBackend, nil)
	require.NoError(t, err)
	defer l.Shutdown()
	after, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, os.SameFile(before, after))

	tc := thin.NewThinClient(thin.FromConfig(cfg), &config.Logging{Level: "ERROR"})
	require.NoError(t, tc.Dial())
	require.NoError(t, tc.Close())
}
