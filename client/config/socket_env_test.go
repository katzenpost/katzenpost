// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"os"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/transport"
)

func encodeConfig(t *testing.T, cfg any) []byte {
	t.Helper()
	var b bytes.Buffer
	require.NoError(t, toml.NewEncoder(&b).Encode(cfg))
	return b.Bytes()
}

func withUnixListen(t *testing.T, address string) []byte {
	t.Helper()
	raw := make(map[string]any)
	_, err := toml.DecodeFile(TestClientTOML, &raw)
	require.NoError(t, err)
	raw["Listen"] = &transport.ListenConfig{Unix: &transport.UnixListenConfig{Address: address}}
	return encodeConfig(t, raw)
}

func TestLoadKeepsSocketEnv(t *testing.T) {
	dir, err := os.MkdirTemp("", "ks")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("KP_TEST_UNSET", "")
	os.Unsetenv("KP_TEST_UNSET")
	cfg, err := Load(withUnixListen(t, "$XDG_RUNTIME_DIR/kpclientd.sock"))
	require.NoError(t, err)
	require.Contains(t, string(encodeConfig(t, cfg)), `Address = "$XDG_RUNTIME_DIR/kpclientd.sock"`)
	l, err := cfg.Listen.Listen()
	require.NoError(t, err)
	defer l.Close()
	require.Equal(t, dir+"/kpclientd.sock", l.Addr().String())

	_, err = Load(withUnixListen(t, "$KP_TEST_UNSET/kpclientd.sock"))
	require.ErrorContains(t, err, "KP_TEST_UNSET is unset or empty")
}
