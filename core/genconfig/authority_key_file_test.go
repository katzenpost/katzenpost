// SPDX-License-Identifier: AGPL-3.0-only

package genconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
)

func genAuthority(t *testing.T) (string, *vConfig.Config) {
	t.Helper()
	out := t.TempDir()
	cfg := Config{
		NrLayers:                 3,
		NrNodes:                  3,
		NrGateways:               1,
		NrServiceNodes:           1,
		NrStorageNodes:           2,
		Voting:                   true,
		NrVoting:                 3,
		BaseDir:                  out,
		BasePort:                 35000,
		BindAddr:                 "127.0.0.1",
		OutDir:                   out,
		DockerImage:              "katzenpost-alpine_base",
		LogLevel:                 "DEBUG",
		Wirekem:                  "xwing",
		Nike:                     "x25519",
		UserForwardPayloadLength: 2000,
		PkiSignatureScheme:       "Ed25519 Sphincs+",
		Mu:                       0.005,
		LP:                       0.001,
		LL:                       0.0005,
		LM:                       0.0005,
		LR:                       0.005,
		NoMetrics:                true,
	}
	require.NoError(t, RunGenConfig(cfg))
	path := filepath.Join(out, fmt.Sprintf(AuthNodeFormat, 1), "authority.toml")
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	loaded, err := vConfig.LoadFile(path, false)
	require.NoError(t, err)
	return string(b), loaded
}

func TestGenConfigAuthorityNamesIdentityPublicKeyFile(t *testing.T) {
	text, cfg := genAuthority(t)

	require.Contains(t, text, `IdentityPublicKeyFile = "../mix1/identity.public.pem"`)
	require.Contains(t, text, `IdentityPublicKeyPem = "../mix1/identity.public.pem"`)
	require.NotContains(t, text, `IdentityPublicKeyFile = ""`)
	require.NotContains(t, text, `IdentityPublicKeyPem = ""`)
	require.False(t, cfg.DeprecatedIdentityPublicKeyPem())

	nodes := []vConfig.Node{}
	for _, l := range [][]*vConfig.Node{cfg.Mixes, cfg.GatewayNodes, cfg.ServiceNodes} {
		for _, n := range l {
			nodes = append(nodes, *n)
		}
	}
	require.NotNil(t, cfg.Topology)
	for _, l := range cfg.Topology.Layers {
		nodes = append(nodes, l.Nodes...)
	}
	require.Len(t, nodes, 3+1+1+3)
	for _, n := range nodes {
		require.NotEmpty(t, n.IdentityPublicKeyFile, n.Identifier)
		require.Equal(t, n.IdentityPublicKeyFile, n.IdentityPublicKeyPem, n.Identifier)
	}
	require.Len(t, cfg.StorageReplicas, 2)
	for _, n := range cfg.StorageReplicas {
		require.NotEmpty(t, n.IdentityPublicKeyFile, n.Identifier)
		require.Equal(t, n.IdentityPublicKeyFile, n.IdentityPublicKeyPem, n.Identifier)
	}
}
