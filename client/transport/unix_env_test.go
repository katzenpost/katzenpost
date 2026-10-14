// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnixListenerExpandsEnv(t *testing.T) {
	dir := shortSockDir(t)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Chdir(shortSockDir(t))
	for _, sub := range []string{"$XDG_RUNTIME_DIR/katzenpost", "${XDG_RUNTIME_DIR}", filepath.Join(dir, "katzenpost")} {
		require.NoError(t, os.MkdirAll(sub, 0700))
	}
	cfg := &ListenConfig{Unix: &UnixListenConfig{
		Address:   "$XDG_RUNTIME_DIR/katzenpost/kpclientd.sock",
		Addresses: []string{"${XDG_RUNTIME_DIR}/two.sock"},
	}}
	l, err := cfg.Listen()
	require.NoError(t, err)
	defer l.Close()
	require.Equal(t, dir+"/katzenpost/kpclientd.sock, "+dir+"/two.sock", l.Addr().String())
	require.Equal(t, "$XDG_RUNTIME_DIR/katzenpost/kpclientd.sock", cfg.Unix.Address)
}

func TestUnixListenConfigRejectsBadEnv(t *testing.T) {
	t.Setenv("KP_TEST_UNSET", "")
	os.Unsetenv("KP_TEST_UNSET")
	t.Setenv("KP_TEST_EMPTY", "")
	t.Setenv("KP_TEST_AT", "@")
	for address, want := range map[string]string{
		"$KP_TEST_UNSET/kpclientd.sock":   "KP_TEST_UNSET is unset or empty",
		"${KP_TEST_UNSET}/kpclientd.sock": "KP_TEST_UNSET is unset or empty",
		"$KP_TEST_EMPTY/kpclientd.sock":   "KP_TEST_EMPTY is unset or empty",
		"$KP_TEST_AT":                     "empty unix socket address",
		"/run/$/kpclientd.sock":           "invalid environment variable reference",
		"/run/${KP_TEST_EMPTY":            "invalid environment variable reference",
		"/run/${}/kpclientd.sock":         "invalid environment variable reference",
		"/run/$1/kpclientd.sock":          "invalid environment variable reference",
		"/run/kpclientd.sock$":            "invalid environment variable reference",
	} {
		err := (&ListenConfig{Unix: &UnixListenConfig{Address: "/run/kpclientd.sock", Addresses: []string{address}}}).Validate()
		require.ErrorContains(t, err, want, address)
	}
}

func TestUnixListenerAbstractSkipsEnv(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("abstract unix sockets are Linux-only")
	}
	t.Setenv("KP_TEST_UNSET", "")
	os.Unsetenv("KP_TEST_UNSET")
	address := fmt.Sprintf("@kp-env-%d-$KP_TEST_UNSET", os.Getpid())
	l, err := (&ListenConfig{Unix: &UnixListenConfig{Address: address}}).Listen()
	require.NoError(t, err)
	defer l.Close()
	require.Equal(t, address, l.Addr().String())
}
