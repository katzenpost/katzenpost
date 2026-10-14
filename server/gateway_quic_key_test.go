// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

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
	if c == "generate" {
		generateOnlyGateway(t, cfg, dir)
		return
	}
	if c == "gateway" || c == "nokey" {
		cfg.Server.Identifier = "gateway1"
		cfg.Server.IsGatewayNode = true
		cfg.Gateway = &config.Gateway{}
	}
	require.NoError(t, cfg.FixupAndValidate())
	path := filepath.Join(dir, "quic-tls.key")
	if c == "nokey" {
		s, err := New(cfg)
		if err == nil {
			s.Shutdown()
		}
		require.Error(t, err, "a QUIC gateway started without its quic-tls.key")
		for _, want := range []string{path, "backup", "-g", "genkeypair --type quic", "QUICKeyHash", "PinnedGateways", "client.toml"} {
			require.Contains(t, err.Error(), want)
		}
		_, err = os.Stat(path)
		require.ErrorIs(t, err, os.ErrNotExist, "a normal gateway start created quic-tls.key")
		return
	}
	if c == "gateway" {
		_, err := common.LoadStaticKey(path)
		require.NoError(t, err)
	}
	s, err := New(cfg)
	require.NoError(t, err)
	defer s.Shutdown()
	epoch := common.CurrentEpoch()
	if c == "mix" {
		_, err := os.Stat(path)
		require.ErrorIs(t, err, os.ErrNotExist)
		now, err := s.quicKeys.Hashes(epoch)
		require.NoError(t, err)
		next, err := s.quicKeys.Hashes(epoch + 1)
		require.NoError(t, err)
		require.NotEqual(t, now, next, "a mix stopped rotating its QUIC keys")
		return
	}
	key, err := common.ReadStaticKey(path)
	require.NoError(t, err, "a QUIC gateway kept no long-term quic-tls.key")
	for _, e := range []uint64{epoch, epoch + 1, epoch + 5} {
		hashes, err := s.quicKeys.Hashes(e)
		require.NoError(t, err)
		require.Equal(t, key.Hash(), hashes, "a gateway's descriptor for epoch %d must pin its long-term QUIC key", e)
	}
}

func generatedGatewayPin(t *testing.T, dir string) string {
	t.Helper()
	pin, err := os.ReadFile(filepath.Join(dir, "quic-tls.hash"))
	require.NoError(t, err, "generate-only wrote no quic-tls.hash for a QUIC gateway")
	key, err := common.ReadStaticKey(filepath.Join(dir, "quic-tls.key"))
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(key.Hash())+"\n", string(pin))
	return string(pin[:len(pin)-1])
}

func generateOnlyGateway(t *testing.T, cfg *config.Config, dir string) {
	dir = os.Getenv("KP_QUIC_KEY_DIR")
	cfg.Server.DataDir = dir
	cfg.Server.IdentityPublicKeyFile = filepath.Join(dir, "id.pub")
	cfg.Server.LinkPublicKeyFile = filepath.Join(dir, "link.pub")
	cfg.Logging.File = filepath.Join(dir, "server.log")
	cfg.Server.Identifier = "gateway1"
	cfg.Server.IsGatewayNode = true
	cfg.Server.Addresses = []string{"quic://" + os.Getenv("KP_QUIC_KEY_ADDR")}
	cfg.Gateway = &config.Gateway{}
	cfg.Debug.GenerateOnly = os.Getenv("KP_QUIC_KEY_START") == ""
	require.NoError(t, cfg.FixupAndValidate())
	s, err := New(cfg)
	if cfg.Debug.GenerateOnly {
		require.True(t, errors.Is(err, ErrGenerateOnly), "%v", err)
		return
	}
	require.NoError(t, err)
	defer s.Shutdown()
	hash, err := hex.DecodeString(generatedGatewayPin(t, dir))
	require.NoError(t, err)
	u, err := url.Parse("quic://" + os.Getenv("KP_QUIC_KEY_ADDR"))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := common.DialURL(u, ctx, nil, hash, nil)
	require.NoError(t, err, "the gateway did not present the key generate-only pinned")
	conn.Close()
}

func runQUICKeyHelper(t *testing.T, c string, env ...string) {
	if runtime.GOOS == "windows" {
		t.Skip("DataDir's 0700 permission check cannot pass on windows")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestServerQUICKeyHelper$", "-test.count=1")
	cmd.Env = append(append(os.Environ(), "KP_QUIC_KEY_CASE="+c), env...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

func TestGatewayListensOnQUICWithOneLongTermKey(t *testing.T) {
	runQUICKeyHelper(t, "gateway")
}

func TestGatewayRefusesToStartWithoutItsQUICKey(t *testing.T) {
	runQUICKeyHelper(t, "nokey")
}

func TestMixKeepsPerEpochQUICKeys(t *testing.T) {
	runQUICKeyHelper(t, "mix")
}

func TestGenerateOnlyWritesTheGatewayQUICKeyAndPin(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	free, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	addr := free.LocalAddr().String()
	require.NoError(t, free.Close())
	env := []string{"KP_QUIC_KEY_DIR=" + dir, "KP_QUIC_KEY_ADDR=" + addr}
	runQUICKeyHelper(t, "generate", env...)
	pin := generatedGatewayPin(t, dir)
	runQUICKeyHelper(t, "generate", env...)
	require.Equal(t, pin, generatedGatewayPin(t, dir), "generate-only replaced an existing QUIC key")
	runQUICKeyHelper(t, "generate", append(env, "KP_QUIC_KEY_START=1")...)
}
