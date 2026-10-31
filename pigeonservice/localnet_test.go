// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/protocols/sealedbox"

	"github.com/katzenpost/katzenpost/client/localnet"
	ps "github.com/katzenpost/katzenpost/pigeonservice"
	"github.com/katzenpost/katzenpost/pigeonservice/directory"
	"github.com/katzenpost/katzenpost/pigeonservice/router"
)

const localnetPoll = 200 * time.Millisecond

// localnetWorld is a localnet with a voucher router and a service
// directory, each on its own thin connection as on a service node.
func localnetWorld(t *testing.T) *localnet.Network {
	t.Helper()
	n := localnet.New(t)
	n.AddStorage(3)

	routerKey, dirKey := pluginKey(t), pluginKey(t)
	var r *router.Router
	var d *directory.Directory
	var ready sync.WaitGroup
	ready.Add(1)
	n.AddHandler(ps.RouterCapability, ps.PluginParams(routerKey), func(p []byte) []byte {
		ready.Wait()
		return r.Handle(p)
	})
	n.AddHandler(ps.DirectoryCapability, ps.PluginParams(dirKey), func(p []byte) []byte {
		ready.Wait()
		return d.Handle(p)
	})
	n.Start()

	var err error
	r, err = router.New(router.Config{
		Key: routerKey, DBPath: filepath.Join(t.TempDir(), "router.db"),
		PollInterval: localnetPoll, Retention: time.Hour, Log: n.Log.GetLogger("router"),
	}, ps.NewThinPigeonhole(n.ThinClient()))
	require.NoError(t, err)
	t.Cleanup(func() { r.Close() })
	d, err = directory.New(directory.Config{
		Key: dirKey, DBPath: filepath.Join(t.TempDir(), "directory.db"),
		RefreshInterval: time.Hour, Log: n.Log.GetLogger("directory"),
	}, ps.NewThinPigeonhole(n.ThinClient()))
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	ready.Done()
	return n
}

// TestLocalnetEcho is the docker echo scenario on a localnet: the real
// daemon, thin clients, courier and replicas, with the router and the
// directory as hosted plugins. An echo service on one thin connection
// registers and advertises; clients on another look it up, dial it through
// the router, and are echoed, more of them than the service serves at once.
func TestLocalnetEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("runs real CTIDH replicas; a few minutes")
	}
	n := localnetWorld(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	t.Cleanup(cancel)

	servicePh := ps.NewThinPigeonhole(n.ThinClient())
	dataDir := t.TempDir()
	key, err := ps.LoadServiceKey(dataDir)
	require.NoError(t, err)
	adv, err := directory.NewAll(servicePh, key, localnetPoll)
	require.NoError(t, err)
	const limit = 2
	svc, err := ps.NewService(ps.Config{
		Key: key, DataDir: dataDir, DisplayName: "echo", Advertiser: adv,
		PollInterval: localnetPoll, MaxConcurrentSessions: limit,
		Retention: time.Hour, Log: n.Log.GetLogger("echo"),
	}, servicePh)
	require.NoError(t, err)
	svcCtx, stop := context.WithCancel(ctx)
	go svc.Run(svcCtx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
		defer s.Close()
		echoOnce(t, ctx, s)
	}))
	t.Cleanup(func() { stop(); svc.Close() })

	clientPh := ps.NewThinPigeonhole(n.ThinClient())
	reader, err := directory.NewAll(clientPh, nil, localnetPoll)
	require.NoError(t, err)
	var desc *ps.ServiceDescriptor
	for {
		desc, err = reader.Lookup(ctx, svc.ID())
		if err == nil && len(desc.Routers) > 0 {
			break
		}
		require.NoError(t, ctx.Err())
		time.Sleep(localnetPoll)
	}
	t.Log("the directory lists the service")

	const clients = limit + 1
	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := ps.Dial(ctx, clientPh, desc, "client", localnetPoll)
			if err != nil {
				errs <- err
				return
			}
			msg := []byte{'h', 'i', ' ', byte('a' + i)}
			if err := conn.Send(ctx, msg); err != nil {
				errs <- err
				return
			}
			got, err := conn.Recv(ctx)
			if err != nil {
				errs <- err
				return
			}
			if string(got) != "echo: "+string(msg) {
				errs <- context.Canceled
			}
			t.Logf("client %d echoed", i)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

// TestLocalnetRouter registers a service with the voucher router and routes
// a voucher to it at once, while the router may still be finishing the
// induction, then reads the voucher off the link.
func TestLocalnetRouter(t *testing.T) {
	if testing.Short() {
		t.Skip("runs real CTIDH replicas; a minute or two")
	}
	n := localnetWorld(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)
	ph := ps.NewThinPigeonhole(n.ThinClient())
	key, err := ps.LoadServiceKey(t.TempDir())
	require.NoError(t, err)

	nodes, err := ph.Services(ps.RouterCapability)
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	link, err := ps.Register(ctx, ph, key, &nodes[0], localnetPoll)
	require.NoError(t, err)

	desc := &ps.ServiceDescriptor{
		NIKEScheme: key.Scheme.Name(),
		PublicKey:  key.Public.Bytes(),
		Routers:    []ps.RouterRef{{NodeIDHash: nodes[0].NodeIDHash, Endpoint: string(nodes[0].Endpoint)}},
	}
	voucher := make([]byte, 32)
	copy(voucher, "a voucher for the localnet")
	require.NoError(t, ps.Route(ctx, ph, desc, voucher))
	msg, err := link.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, voucher, openForward(t, key, msg))
}

func openForward(t *testing.T, key *ps.ServiceKey, msg []byte) []byte {
	t.Helper()
	var lm ps.LinkMessage
	require.NoError(t, ps.Unmarshal(msg, &lm))
	v, err := sealedbox.NewScheme(key.Scheme).Open(key.Private, key.Public, lm.Forward)
	require.NoError(t, err)
	return v
}
