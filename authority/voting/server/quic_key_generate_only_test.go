// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/quic/common"
)

func generatedQUICPin(t *testing.T, dir string) string {
	t.Helper()
	pin, err := os.ReadFile(filepath.Join(dir, "quic-tls.hash"))
	require.NoError(t, err, "generate-only wrote no quic-tls.hash")
	key, err := common.ReadStaticKey(filepath.Join(dir, "quic-tls.key"), nil)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(key.Hash())+"\n", string(pin))
	return string(bytes.TrimSpace(pin))
}

func TestGenerateOnlyWritesTheAuthorityQUICKeyAndPin(t *testing.T) {
	cfg, dir := ownKeyConfig(t)
	cfg.Server.Addresses = []string{"quic://127.0.0.1:0"}
	_, err := New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
	pin := generatedQUICPin(t, dir)
	_, err = New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
	require.Equal(t, pin, generatedQUICPin(t, dir), "generate-only replaced an existing QUIC key")

	scheme := signSchemes.ByName(testSchemeName)
	identity, err := signpem.FromPublicPEMFile(filepath.Join(dir, "id.pub"), scheme)
	require.NoError(t, err)
	node := func(name string) *config.Node {
		pub, _, err := scheme.GenerateKey()
		require.NoError(t, err)
		path := filepath.Join(dir, name+".pem")
		require.NoError(t, signpem.PublicKeyToFile(path, pub))
		return &config.Node{Identifier: name, IdentityPublicKeyPem: path}
	}
	cfg.GatewayNodes = []*config.Node{node("gateway1")}
	cfg.ServiceNodes = []*config.Node{node("servicenode1")}
	cfg.Authorities[0].IdentityPublicKey = identity
	cfg.Authorities[0].QUICKeyHash, err = hex.DecodeString(pin)
	require.NoError(t, err)
	cfg.Debug.GenerateOnly = false
	limit := 8
	cfg.Debug.MaxClientConns, cfg.Debug.MaxConnsPerIP = &limit, &limit
	s, err := New(cfg)
	require.NoError(t, err)
	defer s.Shutdown()
	u, err := url.Parse("quic://" + s.listeners[0].Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := common.DialURL(u, ctx, nil, cfg.Authorities[0].QUICKeyHash, nil)
	require.NoError(t, err, "the authority did not present the key generate-only pinned")
	conn.Close()
}

func TestGenerateOnlyKeepsRefusingAMissingPinnedAuthorityQUICKey(t *testing.T) {
	cfg, dir := ownKeyConfig(t)
	_, err := New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
	identity, err := signpem.FromPublicPEMFile(filepath.Join(dir, "id.pub"), signSchemes.ByName(testSchemeName))
	require.NoError(t, err)
	cfg.Authorities[0].IdentityPublicKey = identity
	cfg.Authorities[0].QUICKeyHash = bytes.Repeat([]byte{2}, 32)
	cfg.Server.Addresses = []string{"quic://127.0.0.1:0"}
	_, err = New(cfg)
	require.ErrorContains(t, err, "quic-tls.key", "generate-only made a new key for a pinned authority")
	require.NoFileExists(t, filepath.Join(dir, "quic-tls.key"))
}

func TestGenerateOnlyWritesNoQUICKeyForATCPOnlyAuthority(t *testing.T) {
	cfg, dir := ownKeyConfig(t)
	cfg.Server.Addresses = []string{"tcp://127.0.0.1:0"}
	_, err := New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
	require.NoFileExists(t, filepath.Join(dir, "quic-tls.key"))
	require.NoFileExists(t, filepath.Join(dir, "quic-tls.hash"))
}
