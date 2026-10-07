// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

const reloadScheme = testSchemeName

type reloadNode struct {
	name string
	pub  sign.PublicKey
	pem  string
}

func newReloadNode(t *testing.T, dataDir, name string) reloadNode {
	pub, _, err := signSchemes.ByName(reloadScheme).GenerateKey()
	require.NoError(t, err)
	pemName := name + ".pem"
	require.NoError(t, signpem.PublicKeyToFile(filepath.Join(dataDir, pemName), pub))
	return reloadNode{name: name, pub: pub, pem: pemName}
}

func (n reloadNode) mix() *config.Node {
	return &config.Node{Identifier: n.name, IdentityPublicKeyPem: n.pem}
}

func (n reloadNode) desc(t *testing.T) *pki.MixDescriptor {
	raw, err := n.pub.MarshalBinary()
	require.NoError(t, err)
	return &pki.MixDescriptor{Name: n.name, IdentityKey: raw}
}

func (n reloadNode) hash() []byte {
	h := hash.Sum256From(n.pub)
	return h[:]
}

func reloadTestServer(t *testing.T, dataDir string) (*Server, string) {
	logFile := filepath.Join(t.TempDir(), "reload.log")
	backend, err := log.New(logFile, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	srv := &Server{
		cfg: &config.Config{
			Server: &config.Server{DataDir: dataDir, PKISignatureScheme: reloadScheme},
			Debug:  &config.Debug{Layers: 1, MinNodesPerLayer: 1},
		},
		logBackend: backend,
		log:        backend.GetLogger("server"),
	}
	srv.state = &state{s: srv, log: backend.GetLogger("state")}
	return srv, logFile
}

func reloadConfig(t *testing.T, dataDir string, mixes []*config.Node, replicas []*config.StorageReplicaNode) *config.Config {
	return &config.Config{
		Server:          &config.Server{DataDir: dataDir, PKISignatureScheme: reloadScheme},
		GatewayNodes:    []*config.Node{newReloadNode(t, dataDir, "gateway").mix()},
		ServiceNodes:    []*config.Node{newReloadNode(t, dataDir, "service").mix()},
		Mixes:           mixes,
		StorageReplicas: replicas,
	}
}

func TestReloadNodesChangesAuthorizedSet(t *testing.T) {
	dataDir := t.TempDir()
	a := newReloadNode(t, dataDir, "mixA")
	b := newReloadNode(t, dataDir, "mixB")
	r := newReloadNode(t, dataDir, "replica1")
	srv, logFile := reloadTestServer(t, dataDir)
	st := srv.state

	require.NoError(t, srv.ReloadNodes(reloadConfig(t, dataDir, []*config.Node{a.mix()}, nil)))
	require.NoError(t, st.descriptorAuthorizationError(a.desc(t)))
	require.Error(t, st.descriptorAuthorizationError(b.desc(t)))
	require.Equal(t, "mixA", st.PeerName(a.hash()))

	rawR, err := r.pub.MarshalBinary()
	require.NoError(t, err)
	replicaDesc := &pki.ReplicaDescriptor{Name: "replica1", ReplicaID: 1, IdentityKey: rawR}
	require.Error(t, st.replicaAuthorizationError(replicaDesc))

	replicas := []*config.StorageReplicaNode{{Identifier: "replica1", IdentityPublicKeyPem: r.pem, ReplicaID: 1}}
	require.NoError(t, srv.ReloadNodes(reloadConfig(t, dataDir, []*config.Node{b.mix()}, replicas)))
	require.Error(t, st.descriptorAuthorizationError(a.desc(t)))
	require.NoError(t, st.descriptorAuthorizationError(b.desc(t)))
	require.NoError(t, st.replicaAuthorizationError(replicaDesc))
	require.Equal(t, "", st.PeerName(a.hash()))
	require.Equal(t, "mixB", st.PeerName(b.hash()))

	bad := reloadConfig(t, dataDir, []*config.Node{a.mix(), {Identifier: "ghost", IdentityPublicKeyPem: "missing.pem"}}, nil)
	require.Error(t, srv.ReloadNodes(bad))
	require.Error(t, st.descriptorAuthorizationError(a.desc(t)))
	require.NoError(t, st.descriptorAuthorizationError(b.desc(t)))
	require.NoError(t, st.replicaAuthorizationError(replicaDesc))

	out, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(out), "ERRO")
	require.Contains(t, string(out), "missing.pem")
}

func TestReloadNodesConcurrentWithReaders(t *testing.T) {
	dataDir := t.TempDir()
	a := newReloadNode(t, dataDir, "mixA")
	b := newReloadNode(t, dataDir, "mixB")
	srv, _ := reloadTestServer(t, dataDir)
	st := srv.state
	cfgA := reloadConfig(t, dataDir, []*config.Node{a.mix()}, nil)
	cfgB := reloadConfig(t, dataDir, []*config.Node{b.mix()}, nil)
	require.NoError(t, srv.ReloadNodes(cfgA))

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = st.descriptorAuthorizationError(a.desc(t))
				_ = st.PeerName(b.hash())
				_ = st.isNodePeer(hash.Sum256From(a.pub))
			}
		}()
	}
	for i := 0; i < 20; i++ {
		cfg := cfgA
		if i%2 == 1 {
			cfg = cfgB
		}
		require.NoError(t, srv.ReloadNodes(cfg))
	}
	close(stop)
	wg.Wait()
	require.NoError(t, st.descriptorAuthorizationError(b.desc(t)))
}

func TestReloadNodesRefusesTooFewNodes(t *testing.T) {
	dataDir := t.TempDir()
	a := newReloadNode(t, dataDir, "mixA")
	b := newReloadNode(t, dataDir, "mixB")
	srv, _ := reloadTestServer(t, dataDir)
	st := srv.state
	require.NoError(t, srv.ReloadNodes(reloadConfig(t, dataDir, []*config.Node{a.mix()}, nil)))

	noGateway := reloadConfig(t, dataDir, []*config.Node{b.mix()}, nil)
	noGateway.GatewayNodes = nil
	require.Error(t, srv.ReloadNodes(noGateway))

	noService := reloadConfig(t, dataDir, []*config.Node{b.mix()}, nil)
	noService.ServiceNodes = nil
	require.Error(t, srv.ReloadNodes(noService))

	srv.cfg.Debug = &config.Debug{Layers: 2, MinNodesPerLayer: 1}
	require.Error(t, srv.ReloadNodes(reloadConfig(t, dataDir, []*config.Node{b.mix()}, nil)))

	require.NoError(t, st.descriptorAuthorizationError(a.desc(t)))
	require.Error(t, st.descriptorAuthorizationError(b.desc(t)))
}
