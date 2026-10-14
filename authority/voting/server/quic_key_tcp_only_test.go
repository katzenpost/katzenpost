// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
)

func TestTCPOnlyAuthorityStartsWithoutItsPinnedQUICKey(t *testing.T) {
	cfg, dir := ownKeyConfig(t)
	_, err := New(cfg)
	require.ErrorIs(t, err, ErrGenerateOnly)
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
	cfg.Authorities[0].QUICKeyHash = bytes.Repeat([]byte{2}, 32)
	cfg.Server.Addresses = []string{"tcp://127.0.0.1:0"}
	cfg.Debug.GenerateOnly = false
	limit := 8
	cfg.Debug.MaxClientConns, cfg.Debug.MaxConnsPerIP = &limit, &limit
	s, err := New(cfg)
	require.NoError(t, err, "a tcp-only authority refused to start over its QUIC key")
	s.Shutdown()
	_, err = os.Stat(filepath.Join(dir, "quic-tls.key"))
	require.ErrorIs(t, err, os.ErrNotExist)
}
