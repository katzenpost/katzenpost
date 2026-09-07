// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

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

func TestUnixListenerMultiple(t *testing.T) {
	tmpDir := shortSockDir(t)
	paths := []string{filepath.Join(tmpDir, "one.sock"), filepath.Join(tmpDir, "two.sock")}
	l, err := (&UnixListenConfig{Address: paths[0], Addresses: paths[1:]}).Listen()
	require.NoError(t, err)
	require.Contains(t, l.Addr().String(), paths[0])
	require.Contains(t, l.Addr().String(), paths[1])
	defer l.Close()
	for _, path := range paths {
		client, err := net.Dial("unix", path)
		require.NoError(t, err)
		server, err := l.Accept()
		require.NoError(t, err)
		require.NoError(t, client.Close())
		require.NoError(t, server.Close())
	}
	require.NoError(t, l.Close())
	_, err = l.Accept()
	require.Error(t, err)
}

func TestUnixListenerClosesAfterBindFailure(t *testing.T) {
	tmpDir := shortSockDir(t)
	first := filepath.Join(tmpDir, "one.sock")
	l, err := (&UnixListenConfig{Address: first, Addresses: []string{filepath.Join(tmpDir, "missing", "two.sock")}}).Listen()
	require.Error(t, err)
	require.Nil(t, l)
	_, err = net.Dial("unix", first)
	require.Error(t, err)
}

func TestUnixListenerAbstractAndFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("abstract unix sockets are Linux-only")
	}
	tmpDir := shortSockDir(t)
	// Unique per process: abstract names share one namespace-global table.
	abstract := fmt.Sprintf("@kpclientd-test-%d.sock", os.Getpid())
	file := filepath.Join(tmpDir, "file.sock")
	l, err := (&UnixListenConfig{Address: abstract, Addresses: []string{file}}).Listen()
	require.NoError(t, err)
	require.Contains(t, l.Addr().String(), abstract)
	require.Contains(t, l.Addr().String(), file)
	defer l.Close()

	for _, name := range []string{abstract, file} {
		client, err := net.Dial("unix", name)
		require.NoError(t, err, "dial %s", name)
		server, err := l.Accept()
		require.NoError(t, err)
		require.NoError(t, client.Close())
		require.NoError(t, server.Close())
	}

	// The file socket exists on disk; the abstract one does not.
	_, err = os.Stat(file)
	require.NoError(t, err)
	_, err = os.Stat(abstract)
	require.Error(t, err)
}

// Close must not hang or leak with a connection accepted but undelivered.
func TestUnixListenerCloseDrainsInFlight(t *testing.T) {
	tmpDir := shortSockDir(t)
	paths := []string{filepath.Join(tmpDir, "one.sock"), filepath.Join(tmpDir, "two.sock")}
	l, err := (&UnixListenConfig{Address: paths[0], Addresses: paths[1:]}).Listen()
	require.NoError(t, err)

	client, err := net.Dial("unix", paths[1])
	require.NoError(t, err)
	defer client.Close()
	// Let the accept goroutine park on the unbuffered channel with no reader.
	time.Sleep(50 * time.Millisecond)

	closeErr := make(chan error, 1)
	go func() { closeErr <- l.Close() }()
	select {
	case err := <-closeErr:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung with an in-flight connection")
	}

	_, err = l.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestUnixListenerRejectsEmptyAddress(t *testing.T) {
	l, err := (&UnixListenConfig{Address: ""}).Listen()
	require.Error(t, err)
	require.Nil(t, l)
	// A bare '@' is a nameless abstract socket (kernel autobind); reject.
	l, err = (&UnixListenConfig{Address: "@"}).Listen()
	require.Error(t, err)
	require.Nil(t, l)
}

func TestUnixListenConfigValidateRejectsEmpty(t *testing.T) {
	require.Error(t, (&ListenConfig{Unix: &UnixListenConfig{Address: ""}}).Validate())
	require.Error(t, (&ListenConfig{Unix: &UnixListenConfig{Address: "@"}}).Validate())
	require.NoError(t, (&ListenConfig{Unix: &UnixListenConfig{Address: "/tmp/x.sock"}}).Validate())
}

// tempError is a net.Error reporting itself as temporary, like EMFILE.
type tempError struct{}

func (tempError) Error() string   { return "temporary" }
func (tempError) Timeout() bool   { return false }
func (tempError) Temporary() bool { return true }

// fakeListener drives multiListener's accept goroutine from a test.
type fakeListener struct {
	closed    chan struct{}
	closeOnce sync.Once
	acceptFn  func(closed <-chan struct{}) (net.Conn, error)
}

func newFake(fn func(closed <-chan struct{}) (net.Conn, error)) *fakeListener {
	return &fakeListener{closed: make(chan struct{}), acceptFn: fn}
}

func (f *fakeListener) Accept() (net.Conn, error) { return f.acceptFn(f.closed) }
func (f *fakeListener) Close() error              { f.closeOnce.Do(func() { close(f.closed) }); return nil }
func (f *fakeListener) Addr() net.Addr            { return &net.UnixAddr{Name: "fake", Net: "unix"} }

type fakeLogger struct {
	mu  sync.Mutex
	msg string
}

func (l *fakeLogger) Errorf(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msg = fmt.Sprintf(format, args...)
}

func (l *fakeLogger) last() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.msg
}

func TestMultiListenerMemberFailureKeepsServing(t *testing.T) {
	dir := shortSockDir(t)
	path := filepath.Join(dir, "live.sock")
	live, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	failing := newFake(func(<-chan struct{}) (net.Conn, error) { return nil, errors.New("boom") })

	log := &fakeLogger{}
	m := newMultiListener([]Listener{live, failing}, log)
	defer m.Close()

	client, err := net.Dial("unix", path)
	require.NoError(t, err)
	defer client.Close()
	conn, err := m.Accept()
	require.NoError(t, err) // the failing member's error is not surfaced
	require.NoError(t, conn.Close())

	// The failing member was closed on retirement so dialers get refused,
	// and the retirement was logged.
	require.Eventually(t, func() bool {
		select {
		case <-failing.closed:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
	require.Contains(t, log.last(), "retired")
}

func TestMultiListenerAllMembersFailDrains(t *testing.T) {
	dead := func(<-chan struct{}) (net.Conn, error) { return nil, errors.New("dead") }
	m := newMultiListener([]Listener{newFake(dead), newFake(dead)}, nil)
	_, err := m.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
	require.NoError(t, m.Close())
}

func TestMultiListenerTemporaryErrorRetries(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	var mu sync.Mutex
	var calls int
	fake := newFake(func(closed <-chan struct{}) (net.Conn, error) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		switch n {
		case 1:
			return nil, tempError{} // must be retried, not retired
		case 2:
			return server, nil
		default:
			<-closed
			return nil, net.ErrClosed
		}
	})
	m := newMultiListener([]Listener{fake}, nil)
	defer m.Close()

	conn, err := m.Accept()
	require.NoError(t, err)
	require.Equal(t, server, conn)
	require.NoError(t, conn.Close())
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
	address := fmt.Sprintf("@kpclientd-stale-%d", os.Getpid())

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
