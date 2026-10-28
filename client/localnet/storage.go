// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package localnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stretchr/testify/require"

	kemPEM "github.com/katzenpost/hpqc/kem/pem"
	nikePem "github.com/katzenpost/hpqc/nike/pem"
	"github.com/katzenpost/hpqc/sign"
	signPem "github.com/katzenpost/hpqc/sign/pem"

	dirauthConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/selfcheckcache"
	courierServer "github.com/katzenpost/katzenpost/courier/server"
	courierConfig "github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/replica"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	replicaConfig "github.com/katzenpost/katzenpost/replica/config"
)

// pkiClient serves the network's consensus to its couriers and replicas.
// It withholds it until released, so no replica dials its peers before
// they are all listening: a refused dial backs off for a sizeable part of
// an epoch.
type pkiClient struct {
	auth     *authority
	released atomic.Bool
}

var errNotReleased = errors.New("localnet: consensus not yet released")

func (c *pkiClient) GetPKIDocumentForEpoch(_ context.Context, epoch uint64) (*pki.Document, []byte, error) {
	if !c.released.Load() {
		return nil, nil, errNotReleased
	}
	return c.auth.document(epoch)
}

func (c *pkiClient) Deserialize(raw []byte) (*pki.Document, error) {
	return pki.ParseDocument(raw)
}

func (c *pkiClient) Post(context.Context, uint64, sign.PrivateKey, sign.PublicKey, *pki.MixDescriptor, *loops.LoopStats) error {
	return nil
}

func (c *pkiClient) PostReplica(_ context.Context, epoch uint64, _ sign.PrivateKey, _ sign.PublicKey, d *pki.ReplicaDescriptor) error {
	return pki.IsReplicaDescriptorWellFormed(d, epoch)
}

// placeholderAuthorities fills the voting section the courier and replica
// configs require; with pkiClient they never contact an authority.
func placeholderAuthorities() []*dirauthConfig.Authority {
	return []*dirauthConfig.Authority{{
		Identifier:         "auth",
		PKISignatureScheme: signSchemeName,
		WireKEMScheme:      wireKEMName,
		Addresses:          []string{""},
	}}
}

// selfCheck holds the first replica's CTIDH self-check result. Every later
// replica in the process starts from it instead of spending seconds
// measuring the same host again.
var selfCheck struct {
	mu   sync.Mutex
	blob []byte
}

type storageReplica struct {
	cfg    *replicaConfig.Config
	server *replica.Server
}

// AddStorage adds n storage replicas and a courier, served on the service
// node under the courier capability. Call it before Start.
func (n *Network) AddStorage(replicas int) {
	t := n.t
	t.Helper()
	require.False(t, n.started, "localnet: storage is added before Start")
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	for i := range replicas {
		dir := filepath.Join(n.dir, fmt.Sprintf("replica%d", i))
		require.NoError(t, os.MkdirAll(dir, 0700))
		addr := fmt.Sprintf("tcp://%s", freeAddr(t))
		cfg := &replicaConfig.Config{
			DisableDecoyTraffic: true,
			DataDir:             dir,
			Identifier:          fmt.Sprintf("replica%d", i),
			WireKEMScheme:       wireKEMName,
			PKISignatureScheme:  signSchemeName,
			ReplicaNIKEScheme:   replicaCommon.NikeScheme.Name(),
			SphinxGeometry:      n.Geo,
			Addresses:           []string{addr},
			ReplyHandoffTimeout: 60000,
			ConnectTimeout:      60000,
			HandshakeTimeout:    30000,
			ReauthInterval:      300000,
			ProxyWorkerCount:    8,
			ProxyRequestTimeout: 300,
			Logging:             &replicaConfig.Logging{File: filepath.Join(dir, "replica.log"), Level: "DEBUG"},
			PKI:                 &replicaConfig.PKI{Voting: &replicaConfig.Voting{Authorities: placeholderAuthorities()}},
		}

		envPub, envPriv, err := replicaCommon.NikeScheme.GenerateKeyPair()
		require.NoError(t, err)
		require.NoError(t, nikePem.PrivateKeyToFile(filepath.Join(dir, fmt.Sprintf("replica.%d.private.pem", replicaEpoch)), envPriv, replicaCommon.NikeScheme))
		require.NoError(t, nikePem.PublicKeyToFile(filepath.Join(dir, fmt.Sprintf("replica.%d.public.pem", replicaEpoch)), envPub, replicaCommon.NikeScheme))
		idPub, idPriv, err := signScheme.GenerateKey()
		require.NoError(t, err)
		require.NoError(t, signPem.PrivateKeyToFile(filepath.Join(dir, "identity.private.pem"), idPriv))
		require.NoError(t, signPem.PublicKeyToFile(filepath.Join(dir, "identity.public.pem"), idPub))
		linkPub, linkPriv, err := wireKEM.GenerateKeyPair()
		require.NoError(t, err)
		require.NoError(t, kemPEM.PrivateKeyToFile(filepath.Join(dir, "link.private.pem"), linkPriv))
		require.NoError(t, kemPEM.PublicKeyToFile(filepath.Join(dir, "link.public.pem"), linkPub))

		idBytes, err := idPub.MarshalBinary()
		require.NoError(t, err)
		linkBytes, err := linkPub.MarshalBinary()
		require.NoError(t, err)
		n.auth.replicas = append(n.auth.replicas, &pki.ReplicaDescriptor{
			Name:         cfg.Identifier,
			ReplicaID:    uint8(i),
			IdentityKey:  idBytes,
			LinkKey:      linkBytes,
			Addresses:    map[string][]string{"tcp": {addr}},
			EnvelopeKeys: map[uint64][]byte{replicaEpoch: envPub.Bytes()},
		})
		n.replicas = append(n.replicas, &storageReplica{cfg: cfg})
	}

	dir := filepath.Join(n.dir, "courier")
	require.NoError(t, os.MkdirAll(dir, 0700))
	linkPub, linkPriv, err := wireKEM.GenerateKeyPair()
	require.NoError(t, err)
	require.NoError(t, kemPEM.PrivateKeyToFile(filepath.Join(dir, "link.private.pem"), linkPriv))
	require.NoError(t, kemPEM.PublicKeyToFile(filepath.Join(dir, "link.public.pem"), linkPub))
	n.courierCfg = &courierConfig.Config{
		DataDir:             dir,
		WireKEMScheme:       wireKEMName,
		PKIScheme:           signSchemeName,
		EnvelopeScheme:      replicaCommon.NikeScheme.Name(),
		SphinxGeometry:      n.Geo,
		ConnectTimeout:      60000,
		HandshakeTimeout:    30000,
		ReauthInterval:      300000,
		DisableDecoyTraffic: true,
		MaxQueueSize:        courierConfig.DefaultMaxQueueSize,
		Logging:             &courierConfig.Logging{File: filepath.Join(dir, "courier.log"), Level: "DEBUG"},
		PKI:                 &courierConfig.PKI{Voting: &courierConfig.Voting{Authorities: placeholderAuthorities()}},
	}
	n.courierParams = map[string]interface{}{"linkPublicKey": kemPEM.ToPublicPEMString(linkPub)}
	n.auth.service.desc.Kaetzchen[constants.CourierServiceName] = map[string]interface{}{"endpoint": constants.CourierServiceName}
	n.auth.service.desc.KaetzchenAdvertizedData[constants.CourierServiceName] = n.courierParams
}

// startStorage starts the replicas and the courier and waits until the
// replicas are meshed and the courier holds a consensus.
func (n *Network) startStorage() {
	t := n.t
	t.Helper()
	if n.courierCfg == nil {
		return
	}
	pc := &pkiClient{auth: n.auth}
	for _, r := range n.replicas {
		selfCheck.mu.Lock()
		if selfCheck.blob != nil {
			require.NoError(t, os.WriteFile(selfcheckcache.PathIn(r.cfg.DataDir), selfCheck.blob, 0600))
		}
		selfCheck.mu.Unlock()
		var err error
		r.server, err = replica.NewWithPKI(r.cfg, pc)
		require.NoError(t, err)
		selfCheck.mu.Lock()
		if selfCheck.blob == nil {
			selfCheck.blob, _ = os.ReadFile(selfcheckcache.PathIn(r.cfg.DataDir))
		}
		selfCheck.mu.Unlock()
	}
	pc.released.Store(true)
	for _, r := range n.replicas {
		require.NoError(t, r.server.PKIWorker.ForceFetchPKI())
		r.server.ForceConnectorUpdate()
	}
	n.waitReplicaMesh()

	courier, err := courierServer.New(n.courierCfg, pc)
	require.NoError(t, err)
	n.courier = courier
	require.NoError(t, courier.PKI.ForceFetchPKI())
	courier.ForceConnectorUpdate()
	courier.Courier.SetWriteFunc(n.gw.reply)
	n.gw.plugins[constants.CourierServiceName] = &hostedPlugin{plugin: courier.Courier}
}

func (n *Network) waitReplicaMesh() {
	t := n.t
	t.Helper()
	want := len(n.replicas) - 1
	deadline := time.Now().Add(epochtime.Period()/4 + 2*time.Minute)
	for {
		ready := true
		for _, r := range n.replicas {
			if r.server.SessionCount() < want {
				ready = false
			}
		}
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("localnet: the replicas did not mesh")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (n *Network) stopStorage() {
	for _, r := range n.replicas {
		if r.server != nil {
			r.server.Shutdown()
			r.server.Wait()
		}
	}
}

func freeAddr(t require.TestingT) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().String()
}
