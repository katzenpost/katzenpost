// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// shortSockDir returns a temporary directory with a short path, suitable
// for unix sockets on macOS where sockaddr_un.sun_path is capped at 104
// bytes. t.TempDir embeds the test name and produces paths that can
// exceed the limit.
func shortSockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ks")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestUnixListenerRoundtrip(t *testing.T) {
	tmpDir := shortSockDir(t)
	sockPath := filepath.Join(tmpDir, "test.sock")

	cfg := &UnixListenConfig{Address: sockPath}
	l, err := cfg.Listen()
	require.NoError(t, err)
	defer l.Close()

	want := []byte("hello, unix")
	errCh := make(chan error, 1)
	go func() {
		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		if _, err := conn.Write(want); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	acceptedConn, err := l.Accept()
	require.NoError(t, err)
	defer acceptedConn.Close()

	got, err := io.ReadAll(&readUntilEOF{acceptedConn, len(want)})
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.NoError(t, <-errCh)
}

func TestListenConfigListen_Unix(t *testing.T) {
	tmpDir := shortSockDir(t)
	sockPath := filepath.Join(tmpDir, "dispatch.sock")

	cfg := &ListenConfig{Unix: &UnixListenConfig{Address: sockPath}}
	l, err := cfg.Listen()
	require.NoError(t, err)
	defer l.Close()

	require.Equal(t, "unix", l.Addr().Network())
	require.Equal(t, sockPath, l.Addr().String())
}

// readUntilEOF wraps a net.Conn and signals EOF after n bytes so
// io.ReadAll terminates. The thin-client framing layer uses a length
// prefix; the tests here do not, and need an explicit stopping rule.
type readUntilEOF struct {
	r         net.Conn
	remaining int
}

func (r *readUntilEOF) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.r.Read(p)
	r.remaining -= n
	if err == nil && r.remaining <= 0 {
		err = io.EOF
	}
	return n, err
}

func TestUnixListenerRepairsStaleSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stale socket repair relies on POSIX unix socket semantics")
	}
	tmpDir := shortSockDir(t)
	sockPath := filepath.Join(tmpDir, "stale.sock")

	// Emulate a crashed daemon: a listener whose socket file survives
	// because SetUnlinkOnClose(false) skips the unlink that a clean
	// shutdown would perform.
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	require.NoError(t, err)
	crashed, err := net.ListenUnix("unix", addr)
	require.NoError(t, err)
	crashed.SetUnlinkOnClose(false)
	require.NoError(t, crashed.Close())

	fi, err := os.Stat(sockPath)
	require.NoError(t, err, "the stale socket file must survive the crash")
	require.NotZero(t, fi.Mode()&os.ModeSocket)

	cfg := &UnixListenConfig{Address: sockPath}
	l, err := cfg.Listen()
	require.NoError(t, err, "a stale socket must not block the next bind")
	defer l.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			errCh <- err
			return
		}
		conn.Close()
		errCh <- nil
	}()
	acceptedConn, err := l.Accept()
	require.NoError(t, err)
	acceptedConn.Close()
	require.NoError(t, <-errCh)
}

func TestUnixListenerKeepsLiveSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stale socket repair relies on POSIX unix socket semantics")
	}
	tmpDir := shortSockDir(t)
	sockPath := filepath.Join(tmpDir, "live.sock")

	live := &UnixListenConfig{Address: sockPath}
	first, err := live.Listen()
	require.NoError(t, err)
	defer first.Close()

	// A second bind on a socket a live daemon still answers on must
	// fail rather than evict the running daemon.
	_, err = (&UnixListenConfig{Address: sockPath}).Listen()
	require.Error(t, err)

	fi, statErr := os.Stat(sockPath)
	require.NoError(t, statErr, "the live socket file must be left in place")
	require.NotZero(t, fi.Mode()&os.ModeSocket)

	errCh := make(chan error, 1)
	go func() {
		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			errCh <- err
			return
		}
		conn.Close()
		errCh <- nil
	}()
	acceptedConn, err := first.Accept()
	require.NoError(t, err, "the original listener must still be serving")
	acceptedConn.Close()
	require.NoError(t, <-errCh)
}

func TestUnixListenerLeavesRegularFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stale socket repair relies on POSIX unix socket semantics")
	}
	tmpDir := shortSockDir(t)
	filePath := filepath.Join(tmpDir, "regular.file")
	require.NoError(t, os.WriteFile(filePath, []byte("not a socket"), 0600))

	_, err := (&UnixListenConfig{Address: filePath}).Listen()
	require.Error(t, err, "binding over a regular file must fail")

	got, readErr := os.ReadFile(filePath)
	require.NoError(t, readErr, "a non-socket file must never be removed")
	require.Equal(t, []byte("not a socket"), got)
}

func TestUnixListenerAbstractAddressInUse(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("abstract unix sockets are Linux-only")
	}
	address := "@katzenpost-stale-test"

	first, err := (&UnixListenConfig{Address: address}).Listen()
	require.NoError(t, err)
	defer first.Close()

	// An abstract socket never outlives its owner, so a second bind
	// failing means the first is still live: pass the error through
	// rather than treating it as stale.
	_, err = (&UnixListenConfig{Address: address}).Listen()
	require.Error(t, err)
	require.False(t, staleUnixSocket(address))
}
