// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

func newStateLogged(t *testing.T, cfg *config.Config) (*state, string) {
	logFile := filepath.Join(t.TempDir(), "state.log")
	logBackend, err := log.New(logFile, "DEBUG", false)
	require.NoError(t, err)
	ownPub, _, err := signSchemes.ByName(cfg.Server.PKISignatureScheme).GenerateKey()
	require.NoError(t, err)
	st, err := newState(&Server{cfg: cfg, logBackend: logBackend, identityPublicKey: ownPub})
	require.NoError(t, err)
	t.Cleanup(func() { st.db.Close() })
	return st, logFile
}

func TestNewStateLoadsIdentityPublicKeyFile(t *testing.T) {
	for _, name := range []string{"Ed25519", "Ed25519 Sphincs+"} {
		t.Run(name, func(t *testing.T) {
			f := newNodeKeyFixture(t, signSchemes.ByName(name), "mix0", "mix1", "rep0")
			cfg := &config.Config{
				Server:          &config.Server{DataDir: f.dataDir, PKISignatureScheme: name},
				Mixes:           []*config.Node{{Identifier: "mix0", IdentityPublicKeyFile: f.paths["mix0"]}, {Identifier: "mix1", IdentityPublicKeyFile: f.paths["mix1"]}},
				StorageReplicas: []*config.StorageReplicaNode{{Identifier: "rep0", IdentityPublicKeyFile: f.paths["rep0"]}},
				Topology:        &config.Topology{Layers: []config.Layer{{Nodes: []config.Node{{IdentityPublicKeyFile: f.paths["mix1"]}}}}},
			}
			st, logFile := newStateLogged(t, cfg)

			require.Equal(t, "mix0", st.authorizedMixes[hash.Sum256From(f.keys["mix0"])])
			require.Equal(t, "mix1", st.authorizedMixes[hash.Sum256From(f.keys["mix1"])])
			require.Equal(t, "rep0", st.authorizedReplicaNodes[hash.Sum256From(f.keys["rep0"])].Identifier)

			raw, err := f.keys["mix1"].MarshalBinary()
			require.NoError(t, err)
			topo := st.generateFixedTopology([]*pki.MixDescriptor{{Name: "mix1", IdentityKey: raw}}, nil)
			require.Equal(t, "mix1", topo[0][0].Name)

			out, err := os.ReadFile(logFile)
			require.NoError(t, err)
			require.NotContains(t, string(out), "deprecated")
		})
	}
}

func TestNewStateWarnsOnDeprecatedIdentityPublicKeyPem(t *testing.T) {
	f := newNodeKeyFixture(t, signSchemes.ByName("Ed25519"), "mix0", "mix1")
	cfg := &config.Config{
		Server: &config.Server{DataDir: f.dataDir, PKISignatureScheme: "Ed25519"},
		Mixes:  []*config.Node{{Identifier: "mix0", IdentityPublicKeyFile: f.paths["mix0"]}, {Identifier: "mix1", IdentityPublicKeyPem: f.paths["mix1"]}},
	}
	st, logFile := newStateLogged(t, cfg)
	require.Equal(t, "mix1", st.authorizedMixes[hash.Sum256From(f.keys["mix1"])])

	out, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(out), "WARN")
	require.Contains(t, string(out), "IdentityPublicKeyPem is deprecated, use IdentityPublicKeyFile")
}
