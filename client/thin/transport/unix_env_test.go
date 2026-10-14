// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnixDialExpandsEnv(t *testing.T) {
	dir, err := os.MkdirTemp("", "ks")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
	listener, err := net.Listen("unix", filepath.Join(dir, "kpclientd.sock"))
	require.NoError(t, err)
	defer listener.Close()

	cfg := &DialConfig{Unix: &UnixDialConfig{Address: "${XDG_RUNTIME_DIR}/kpclientd.sock"}}
	conn, err := cfg.Dial()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Equal(t, "${XDG_RUNTIME_DIR}/kpclientd.sock", cfg.Unix.Address)
}

func TestDialConfigRejectsBadEnv(t *testing.T) {
	t.Setenv("KP_TEST_UNSET", "")
	os.Unsetenv("KP_TEST_UNSET")
	t.Setenv("KP_TEST_AT", "@")
	for address, want := range map[string]string{
		"$KP_TEST_UNSET/kpclientd.sock": "KP_TEST_UNSET is unset or empty",
		"$KP_TEST_AT":                   "empty unix socket address",
		"/run/$/kpclientd.sock":         "invalid environment variable reference",
		"":                              "empty unix socket address",
	} {
		err := (&DialConfig{Unix: &UnixDialConfig{Address: address}}).Validate()
		require.ErrorContains(t, err, want, address)
	}
	require.NoError(t, (&DialConfig{Unix: &UnixDialConfig{Address: "@katzenpost-$KP_TEST_UNSET"}}).Validate())
}
