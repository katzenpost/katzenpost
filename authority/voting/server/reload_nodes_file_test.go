// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/wire"
)

func reloadFileFixture(t *testing.T) (*Server, *config.Config, string, string) {
	saved := testSignatureScheme
	testSignatureScheme = signSchemes.ByName(reloadScheme)
	t.Cleanup(func() { testSignatureScheme = saved })
	keys, cfgs, err := genVotingAuthoritiesCfg(&config.Parameters{}, 3)
	require.NoError(t, err)
	cfg := cfgs[0]
	t.Cleanup(func() { os.RemoveAll(cfg.Server.DataDir) })
	require.NoError(t, signpem.PublicKeyToFile(filepath.Join(cfg.Server.DataDir, "identity.public.pem"), keys[0].idPubKey))
	cfg.Server.WireKEMScheme = testingSchemeName
	cfg.Authorities = append(cfg.Authorities, &config.Authority{
		Identifier:         cfg.Server.Identifier,
		PKISignatureScheme: reloadScheme,
		IdentityPublicKey:  keys[0].idPubKey,
		LinkPublicKey:      config.LinkPublicKey{PublicKey: keys[0].linkKey.Public()},
		Addresses:          cfg.Server.Addresses,
	})
	for _, a := range cfg.Authorities {
		a.WireKEMScheme = testingSchemeName
	}
	cfg.Debug = &config.Debug{Layers: 1, MinNodesPerLayer: 1}
	cfg.GatewayNodes = []*config.Node{newReloadNode(t, cfg.Server.DataDir, "gateway").mix()}
	cfg.ServiceNodes = []*config.Node{newReloadNode(t, cfg.Server.DataDir, "service").mix()}
	srv, logFile := reloadTestServer(t, cfg.Server.DataDir)
	srv.cfg = cfg
	srv.identityPublicKey = keys[0].idPubKey
	return srv, cfg, filepath.Join(t.TempDir(), "authority.toml"), logFile
}

func writeReloadConfig(t *testing.T, path string, cfg *config.Config) {
	var buf bytes.Buffer
	require.NoError(t, toml.NewEncoder(&buf).Encode(cfg))
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
}

func TestReloadNodesFromFile(t *testing.T) {
	srv, cfg, path, logFile := reloadFileFixture(t)
	st := srv.state
	a := newReloadNode(t, cfg.Server.DataDir, "mixa")
	b := newReloadNode(t, cfg.Server.DataDir, "mixb")

	cfg.Mixes = []*config.Node{a.mix()}
	writeReloadConfig(t, path, cfg)
	require.NoError(t, srv.ReloadNodesFromFile(path))
	require.NoError(t, st.descriptorAuthorizationError(a.desc(t)))
	require.Error(t, st.descriptorAuthorizationError(b.desc(t)))

	cfg.Mixes = []*config.Node{b.mix()}
	writeReloadConfig(t, path, cfg)
	require.NoError(t, srv.ReloadNodesFromFile(path))
	require.Error(t, st.descriptorAuthorizationError(a.desc(t)))
	require.NoError(t, st.descriptorAuthorizationError(b.desc(t)))

	require.NoError(t, os.WriteFile(path, []byte("[Server\nthis is not toml"), 0o600))
	require.Error(t, srv.ReloadNodesFromFile(path))
	require.NoError(t, st.descriptorAuthorizationError(b.desc(t)), "a broken file keeps the current set")

	require.Error(t, srv.ReloadNodesFromFile(filepath.Join(t.TempDir(), "absent.toml")))
	require.NoError(t, st.descriptorAuthorizationError(b.desc(t)))

	out, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(out), "Node reload failed")
}

func TestReloadNodesKeepsAuthorityKeys(t *testing.T) {
	srv, cfg, _, _ := reloadFileFixture(t)
	st := srv.state
	a := newReloadNode(t, cfg.Server.DataDir, "mixa")
	cfg.Mixes = []*config.Node{a.mix()}
	for i := 0; i < 2; i++ {
		require.NoError(t, srv.ReloadNodes(cfg))
		st.nodesMu.RLock()
		for _, auth := range cfg.Authorities {
			got, ok := st.reverseHash[hash.Sum256From(auth.IdentityPublicKey)]
			require.True(t, ok, auth.Identifier)
			require.True(t, got.Equal(auth.IdentityPublicKey))
		}
		own, ok := st.reverseHash[hash.Sum256From(srv.identityPublicKey)]
		require.True(t, ok)
		require.True(t, own.Equal(srv.identityPublicKey))
		_, ok = st.reverseHash[hash.Sum256From(a.pub)]
		require.True(t, ok)
		st.nodesMu.RUnlock()
	}
}

func TestWireAuthenticatorFollowsReload(t *testing.T) {
	srv, cfg, _, _ := reloadFileFixture(t)
	a := newReloadNode(t, cfg.Server.DataDir, "mixa")
	b := newReloadNode(t, cfg.Server.DataDir, "mixb")
	valid := func(n reloadNode) bool {
		auth := &wireAuthenticator{s: srv}
		return auth.IsPeerValid(&wire.PeerCredentials{AdditionalData: n.hash()})
	}

	cfg.Mixes = []*config.Node{a.mix()}
	require.NoError(t, srv.ReloadNodes(cfg))
	require.True(t, valid(a))
	require.False(t, valid(b))

	cfg.Mixes = []*config.Node{b.mix()}
	require.NoError(t, srv.ReloadNodes(cfg))
	require.False(t, valid(a))
	require.True(t, valid(b))
}

func TestReloadNodesRefusesMissingReplicaKey(t *testing.T) {
	srv, cfg, _, logFile := reloadFileFixture(t)
	st := srv.state
	a := newReloadNode(t, cfg.Server.DataDir, "mixa")
	cfg.Mixes = []*config.Node{a.mix()}
	require.NoError(t, srv.ReloadNodes(cfg))

	cfg.StorageReplicas = []*config.StorageReplicaNode{{Identifier: "ghost", IdentityPublicKeyPem: "ghost-replica.pem", ReplicaID: 1}}
	require.Error(t, srv.ReloadNodes(cfg))
	require.NoError(t, st.descriptorAuthorizationError(a.desc(t)))
	out, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(out), "ghost-replica.pem")
}
