// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/quic/common"
	"github.com/katzenpost/katzenpost/server/config"
)

func TestServerQUICKeyHelper(t *testing.T) {
	c := os.Getenv("KP_QUIC_KEY_CASE")
	if c == "" {
		t.Skip()
	}
	cfg, dir := ownKeyServerConfig(t)
	cfg.Server.Addresses = []string{"quic://127.0.0.1:0"}
	cfg.Debug.GenerateOnly = false
	if c == "gateway" {
		cfg.Server.Identifier = "gateway1"
		cfg.Server.IsGatewayNode = true
		cfg.Gateway = &config.Gateway{}
	}
	require.NoError(t, cfg.FixupAndValidate())
	s, err := New(cfg)
	require.NoError(t, err)
	defer s.Shutdown()
	epoch := common.CurrentEpoch()
	if c == "mix" {
		_, err := os.Stat(filepath.Join(dir, "quic-tls.key"))
		require.ErrorIs(t, err, os.ErrNotExist)
		now, err := s.quicKeys.Hashes(epoch)
		require.NoError(t, err)
		next, err := s.quicKeys.Hashes(epoch + 1)
		require.NoError(t, err)
		require.NotEqual(t, now, next, "a mix stopped rotating its QUIC keys")
		return
	}
	key, err := common.ReadStaticKey(filepath.Join(dir, "quic-tls.key"))
	require.NoError(t, err, "a QUIC gateway kept no long-term quic-tls.key")
	for _, e := range []uint64{epoch, epoch + 1, epoch + 5} {
		hashes, err := s.quicKeys.Hashes(e)
		require.NoError(t, err)
		require.Equal(t, key.Hash(), hashes, "a gateway's descriptor for epoch %d must pin its long-term QUIC key", e)
	}
}

func runQUICKeyHelper(t *testing.T, c string) {
	if runtime.GOOS == "windows" {
		t.Skip("DataDir's 0700 permission check cannot pass on windows")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestServerQUICKeyHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "KP_QUIC_KEY_CASE="+c)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

func TestGatewayListensOnQUICWithOneLongTermKey(t *testing.T) {
	runQUICKeyHelper(t, "gateway")
}

func TestMixKeepsPerEpochQUICKeys(t *testing.T) {
	runQUICKeyHelper(t, "mix")
}
