// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package voucher_router_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/protocols/sealedbox"

	"github.com/katzenpost/katzenpost/client/localnet"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
)

func pluginKey(t *testing.T) *common.PluginKey {
	t.Helper()
	pub, priv, err := common.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	return &common.PluginKey{Scheme: common.DefaultNIKE, Public: pub, Private: priv}
}

const localnetPoll = 200 * time.Millisecond

// localnetWorld is a localnet with a voucher router and a service
// directory, each on its own thin connection as on a service node.
func localnetWorld(t *testing.T) *localnet.Network {
	t.Helper()
	n := localnet.New(t)
	n.AddStorage(3)

	routerKey, dirKey := pluginKey(t), pluginKey(t)
	var r *voucher_router.Router
	var d *discovery.Directory
	var ready sync.WaitGroup
	ready.Add(1)
	n.AddHandler(voucher_router.RouterCapability, common.PluginParams(routerKey), func(p []byte) []byte {
		ready.Wait()
		return r.Handle(p)
	})
	n.AddHandler(discovery.DirectoryCapability, common.PluginParams(dirKey), func(p []byte) []byte {
		ready.Wait()
		return d.Handle(p)
	})
	n.Start()

	var err error
	r, err = voucher_router.New(voucher_router.Config{
		Key: routerKey, DBPath: filepath.Join(t.TempDir(), "router.db"),
		PollInterval: localnetPoll, Retention: time.Hour, Log: n.Log.GetLogger("router"),
	}, common.NewThinPigeonhole(n.ThinClient()))
	require.NoError(t, err)
	t.Cleanup(func() { r.Close() })
	d, err = discovery.New(discovery.Config{
		Key: dirKey, DBPath: filepath.Join(t.TempDir(), "directory.db"),
		RefreshInterval: time.Hour, Log: n.Log.GetLogger("directory"),
	}, common.NewThinPigeonhole(n.ThinClient()))
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	ready.Done()
	return n
}

func TestLocalnetRouter(t *testing.T) {
	if testing.Short() {
		t.Skip("runs real CTIDH replicas; a minute or two")
	}
	n := localnetWorld(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)
	ph := common.NewThinPigeonhole(n.ThinClient())
	key, err := common.LoadServiceKey(t.TempDir())
	require.NoError(t, err)

	nodes, err := ph.Services(voucher_router.RouterCapability)
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	link, err := voucher_router.Register(ctx, ph, key, &nodes[0], localnetPoll)
	require.NoError(t, err)

	desc := &common.ServiceDescriptor{
		NIKEScheme: key.Scheme.Name(),
		PublicKey:  key.Public.Bytes(),
		Routers:    []common.RouterRef{{NodeIDHash: nodes[0].NodeIDHash, Endpoint: string(nodes[0].Endpoint)}},
	}
	voucher := make([]byte, 32)
	copy(voucher, "a voucher for the localnet")
	require.NoError(t, voucher_router.Route(ctx, ph, desc, voucher))
	msg, err := link.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, voucher, openForward(t, key, msg))
}

func openForward(t *testing.T, key *common.ServiceKey, msg []byte) []byte {
	t.Helper()
	var lm voucher_router.LinkMessage
	require.NoError(t, common.Unmarshal(msg, &lm))
	v, err := sealedbox.NewScheme(key.Scheme).Open(key.Private, key.Public, lm.Forward)
	require.NoError(t, err)
	return v
}
