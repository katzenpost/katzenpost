// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package transport

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const activationChild = "KP_TEST_ACTIVATION_CHILD"

func runActivated(t *testing.T, env []string, listeners ...*net.UnixListener) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), activationChild+"=1", "LISTEN_FDS="+strconv.Itoa(len(listeners)), "LISTEN_FDNAMES=kpclientd.sock")
	cmd.Env = append(cmd.Env, env...)
	for _, l := range listeners {
		f, err := l.File()
		require.NoError(t, err)
		defer f.Close()
		cmd.ExtraFiles = append(cmd.ExtraFiles, f)
	}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
}

func listenUnixForChild(t *testing.T, address string) *net.UnixListener {
	t.Helper()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	return l
}

func requireActivationEnvUnset(t *testing.T) {
	t.Helper()
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_, ok := os.LookupEnv(name)
		require.False(t, ok, name)
	}
}

func requireAccepts(t *testing.T, l Listener, address string) {
	t.Helper()
	conn, err := net.Dial("unix", address)
	require.NoError(t, err)
	defer conn.Close()
	accepted, err := l.Accept()
	require.NoError(t, err)
	defer accepted.Close()
	_, err = conn.Write([]byte(address))
	require.NoError(t, err)
	got := make([]byte, len(address))
	_, err = accepted.Read(got)
	require.NoError(t, err)
	require.Equal(t, address, string(got))
}

func TestActivatedUnixListeners(t *testing.T) {
	if os.Getenv(activationChild) == "" {
		path := filepath.Join(shortSockDir(t), "kpclientd.sock")
		abstract := fmt.Sprintf("@kp-activation-%d-a", os.Getpid())
		runActivated(t, []string{"KP_TEST_SOCK=" + path, "KP_TEST_ABSTRACT=" + abstract},
			listenUnixForChild(t, path), listenUnixForChild(t, abstract))
		return
	}
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	path := os.Getenv("KP_TEST_SOCK")
	inherited := os.Getenv("KP_TEST_ABSTRACT")
	bound := fmt.Sprintf("@kp-activation-%d-b", os.Getpid())
	before, err := os.Stat(path)
	require.NoError(t, err)

	l, err := (&ListenConfig{Unix: &UnixListenConfig{Address: inherited, Addresses: []string{path, bound}}}).Listen()
	require.NoError(t, err)
	requireActivationEnvUnset(t)
	after, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, os.SameFile(before, after))

	for _, address := range []string{inherited, path, bound} {
		requireAccepts(t, l, address)
	}
	require.NoError(t, l.Close())
	_, err = os.Stat(path)
	require.NoError(t, err)
}

func TestActivationForAnotherProcessIsIgnored(t *testing.T) {
	if os.Getenv(activationChild) == "" {
		runActivated(t, []string{"LISTEN_PID=1"}, listenUnixForChild(t, fmt.Sprintf("@kp-activation-%d-c", os.Getpid())))
		return
	}
	path := filepath.Join(shortSockDir(t), "kpclientd.sock")
	l, err := (&ListenConfig{Unix: &UnixListenConfig{Address: path}}).Listen()
	require.NoError(t, err)
	defer l.Close()
	requireActivationEnvUnset(t)
	requireAccepts(t, l, path)
	_, err = os.NewFile(3, "inherited").Stat()
	require.NoError(t, err)
}

func TestSystemdSocketActivate(t *testing.T) {
	if os.Getenv(activationChild) != "" {
		path := os.Getenv("KP_TEST_SOCK")
		l, err := (&ListenConfig{Unix: &UnixListenConfig{Address: path}}).Listen()
		require.NoError(t, err)
		defer l.Close()
		requireActivationEnvUnset(t)
		conn, err := l.Accept()
		require.NoError(t, err)
		defer conn.Close()
		_, err = conn.Write([]byte(path))
		require.NoError(t, err)
		return
	}
	activate, err := exec.LookPath("systemd-socket-activate")
	if err != nil {
		t.Skip(err)
	}
	path := filepath.Join(shortSockDir(t), "kpclientd.sock")
	cmd := exec.Command(activate, "-l", path, "-E", activationChild+"=1", "-E", "KP_TEST_SOCK="+path,
		os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	require.NoError(t, cmd.Start())
	var conn net.Conn
	require.Eventually(t, func() bool {
		conn, err = net.Dial("unix", path)
		return err == nil
	}, 10*time.Second, 10*time.Millisecond)
	defer conn.Close()
	got, err := io.ReadAll(conn)
	waitErr := cmd.Wait()
	require.NoError(t, err, out.String())
	require.Equal(t, path, string(got), out.String())
	require.NoError(t, waitErr, out.String())
}

func TestUnmatchedInheritedSocketIsRefused(t *testing.T) {
	for name, cfg := range map[string]func(path string) *ListenConfig{
		"unix": func(path string) *ListenConfig { return &ListenConfig{Unix: &UnixListenConfig{Address: path}} },
		"tcp":  func(string) *ListenConfig { return &ListenConfig{Tcp: &TcpListenConfig{Address: "127.0.0.1:0"}} },
	} {
		t.Run(name, func(t *testing.T) {
			if os.Getenv(activationChild) == "" {
				unmatched := fmt.Sprintf("@kp-activation-%d-%s", os.Getpid(), name)
				runActivated(t, []string{"KP_TEST_ABSTRACT=" + unmatched}, listenUnixForChild(t, unmatched))
				return
			}
			t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
			path := filepath.Join(shortSockDir(t), "kpclientd.sock")
			l, err := cfg(path).Listen()
			require.ErrorContains(t, err, os.Getenv("KP_TEST_ABSTRACT"))
			require.Nil(t, l)
			requireActivationEnvUnset(t)
			_, err = os.Stat(path)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}
