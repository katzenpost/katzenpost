// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package localnet runs a katzenpost network inside one test process,
// without a mixnet: a real client daemon and thin clients, real couriers
// and storage replicas, and real mixnet service plugins, all on one
// consensus the network signs itself. Its gateway does every hop's Sphinx
// processing in place of the mixes, so packets reach their service at once
// and the tests run in seconds instead of minutes.
package localnet

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	vServerConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/client/transport"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	courierServer "github.com/katzenpost/katzenpost/courier/server"
	courierConfig "github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

// UserForwardPayloadLength is the Sphinx user payload size, as on the
// docker mixnet.
const UserForwardPayloadLength = 2000

// Plugin is a mixnet service plugin, such as the courier or a CBOR plugin
// built on pigeonservice/plugin.
type Plugin interface {
	OnCommand(cborplugin.Command) error
}

// Handler serves one request payload with a reply payload.
type Handler func(payload []byte) []byte

type hostedPlugin struct {
	plugin Plugin
}

// handlerPlugin runs a Handler as a plugin.
type handlerPlugin struct {
	h     Handler
	write func(cborplugin.Command)
}

func (p *handlerPlugin) OnCommand(cmd cborplugin.Command) error {
	r, ok := cmd.(*cborplugin.Request)
	if !ok {
		return errors.New("localnet: not a request")
	}
	go p.write(&cborplugin.Response{ID: r.ID, SURB: r.SURB, Payload: p.h(r.Payload)})
	return nil
}

// Network is a katzenpost network in one process.
type Network struct {
	t       testing.TB
	dir     string
	Geo     *geo.Geometry
	Log     *log.Backend
	auth    *authority
	gw      *gateway
	daemon  *client.Daemon
	cfg     *config.Config
	started bool

	replicas      []*storageReplica
	courierCfg    *courierConfig.Config
	courierParams map[string]interface{}
	courier       *courierServer.Server

	mu   sync.Mutex
	thin []*thin.ThinClient
}

// New builds a network's keys and gateway. Add its services, then Start it.
func New(t testing.TB) *Network {
	t.Helper()
	dir := t.TempDir()
	logBackend, err := log.New(filepath.Join(dir, "localnet.log"), "DEBUG", false)
	require.NoError(t, err)
	g := geo.GeometryFromUserForwardPayloadLength(mixNIKE, UserForwardPayloadLength, true, mixLayers+2)
	auth, err := newAuthority(g)
	require.NoError(t, err)
	gw, err := newGateway(auth, g, logBackend.GetLogger("localnet/gateway"))
	require.NoError(t, err)
	n := &Network{t: t, dir: dir, Geo: g, Log: logBackend, auth: auth, gw: gw}
	t.Cleanup(n.close)
	return n
}

// Dir is the network's scratch directory; its logs are in localnet.log
// and kpclientd.log.
func (n *Network) Dir() string { return n.dir }

// AddPlugin hosts a plugin on the service node under capability, which is
// also its endpoint, and publishes params as its advertised data. It
// returns the function the plugin writes its responses with.
func (n *Network) AddPlugin(capability string, params map[string]interface{}, p Plugin) func(cborplugin.Command) {
	n.t.Helper()
	require.False(n.t, n.started, "localnet: services are added before Start")
	svc := n.auth.service
	svc.desc.Kaetzchen[capability] = map[string]interface{}{"endpoint": capability}
	if params != nil {
		svc.desc.KaetzchenAdvertizedData[capability] = params
	}
	n.gw.plugins[capability] = &hostedPlugin{plugin: p}
	return n.gw.reply
}

// AddHandler hosts h on the service node under capability.
func (n *Network) AddHandler(capability string, params map[string]interface{}, h Handler) {
	p := &handlerPlugin{h: h}
	p.write = n.AddPlugin(capability, params, p)
}

// Start starts the storage, the gateway and the client daemon, and waits
// until the daemon holds a consensus.
func (n *Network) Start() {
	t := n.t
	t.Helper()
	n.started = true
	n.startStorage()
	n.gw.start()

	gwID, err := signScheme.UnmarshalBinaryPublicKey(n.auth.gateway.desc.IdentityKey)
	require.NoError(t, err)
	gwLink, err := wireKEM.UnmarshalBinaryPublicKey(n.auth.gateway.desc.LinkKey)
	require.NoError(t, err)
	authLink, _, err := wireKEM.GenerateKeyPair()
	require.NoError(t, err)

	n.cfg = &config.Config{
		Listen: &transport.ListenConfig{
			Unix: &transport.UnixListenConfig{Address: filepath.Join(n.dir, "kpclientd.sock")},
		},
		PKISignatureScheme: signSchemeName,
		WireKEMScheme:      wireKEMName,
		SphinxGeometry:     n.Geo,
		Logging:            &config.Logging{File: filepath.Join(n.dir, "kpclientd.log"), Level: "DEBUG"},
		UpstreamProxy:      &config.UpstreamProxy{Type: "none"},
		Debug:              &config.Debug{DisableDecoyTraffic: true},
		PinnedGateways: &config.Gateways{Gateways: []*config.Gateway{{
			WireKEMScheme:      wireKEMName,
			Name:               n.auth.gateway.desc.Name,
			IdentityKey:        gwID,
			LinkKey:            config.LinkPublicKey{PublicKey: gwLink},
			PKISignatureScheme: signSchemeName,
			Addresses:          []string{n.gw.addr()},
		}}},
		VotingAuthority: &config.VotingAuthority{Peers: []*vServerConfig.Authority{{
			Identifier:         "auth",
			IdentityPublicKey:  n.auth.pub,
			PKISignatureScheme: signSchemeName,
			LinkPublicKey:      vServerConfig.LinkPublicKey{PublicKey: authLink},
			WireKEMScheme:      wireKEMName,
			Addresses:          []string{"tcp://127.0.0.1:1"},
		}}},
	}
	require.NoError(t, n.cfg.FixupAndValidate())
	n.daemon, err = client.NewDaemon(n.cfg)
	require.NoError(t, err)
	require.NoError(t, n.daemon.Start())

	// The first thin client returns once the daemon is connected and
	// holds a consensus.
	n.ThinClient()
}

// ThinClient returns a new thin client connected to the daemon and holding
// a consensus. Each has its own AppID, as separate applications sharing
// one kpclientd do.
func (n *Network) ThinClient() *thin.ThinClient {
	t := n.t
	t.Helper()
	c := thin.NewThinClient(thin.FromConfig(n.cfg), &config.Logging{
		File:  filepath.Join(n.dir, "thin.log"),
		Level: "DEBUG",
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for {
		err := c.Dial()
		if err == nil && c.IsConnected() {
			break
		}
		if err == nil {
			c.Close()
		}
		select {
		case <-ctx.Done():
			require.NoError(t, err, "localnet: the thin client did not connect")
			require.Fail(t, "localnet: the daemon did not connect to the gateway")
		case <-time.After(100 * time.Millisecond):
		}
		c = thin.NewThinClient(thin.FromConfig(n.cfg), &config.Logging{
			File:  filepath.Join(n.dir, "thin.log"),
			Level: "DEBUG",
		})
	}
	for c.PKIDocument() == nil {
		select {
		case <-ctx.Done():
			require.Fail(t, "localnet: the thin client got no consensus")
		case <-time.After(20 * time.Millisecond):
		}
	}
	n.mu.Lock()
	n.thin = append(n.thin, c)
	n.mu.Unlock()
	return c
}

func (n *Network) close() {
	n.mu.Lock()
	clients := n.thin
	n.thin = nil
	n.mu.Unlock()
	for _, c := range clients {
		c.Close()
	}
	if n.daemon != nil {
		n.daemon.Shutdown()
	}
	n.gw.close()
	n.stopStorage()
}
