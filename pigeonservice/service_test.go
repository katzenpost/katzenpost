// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice_test

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	ps "github.com/katzenpost/katzenpost/pigeonservice"
	"github.com/katzenpost/katzenpost/pigeonservice/directory"
	"github.com/katzenpost/katzenpost/pigeonservice/phtest"
	"github.com/katzenpost/katzenpost/pigeonservice/router"
)

type world struct {
	net *phtest.Network
	log *log.Backend
}

func pluginKey(t *testing.T) *ps.PluginKey {
	t.Helper()
	pub, priv, err := ps.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	return &ps.PluginKey{Scheme: ps.DefaultNIKE, Public: pub, Private: priv}
}

// newWorld is a network with two voucher routers and a service directory.
func newWorld(t *testing.T) *world {
	t.Helper()
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	w := &world{net: phtest.NewNetwork(), log: logBackend}
	for i := range 2 {
		key := pluginKey(t)
		r, err := router.New(router.Config{
			Key: key, DBPath: filepath.Join(t.TempDir(), "router.db"),
			PollInterval: poll, Retention: time.Hour, Log: logBackend.GetLogger("router"),
		}, w.net)
		require.NoError(t, err)
		t.Cleanup(func() { r.Close() })
		w.net.AddService(ps.RouterCapability, [32]byte{0xa0 + byte(i)}, ps.RouterCapability, ps.PluginParams(key),
			func(_ context.Context, p []byte) []byte { return r.Handle(p) })
	}
	key := pluginKey(t)
	d, err := directory.New(directory.Config{
		Key: key, DBPath: filepath.Join(t.TempDir(), "directory.db"),
		RefreshInterval: time.Hour, Log: logBackend.GetLogger("directory"),
	}, w.net)
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	w.net.AddService(ps.DirectoryCapability, [32]byte{0xdd}, ps.DirectoryCapability, ps.PluginParams(key),
		func(_ context.Context, p []byte) []byte { return d.Handle(p) })
	return w
}

func (w *world) service(t *testing.T, dataDir string, maxSessions int) *ps.Service {
	t.Helper()
	key, err := ps.LoadServiceKey(dataDir)
	require.NoError(t, err)
	adv, err := directory.NewClient(w.net, key, poll)
	require.NoError(t, err)
	svc, err := ps.NewService(ps.Config{
		Key: key, DataDir: dataDir, DisplayName: "echo", Advertiser: adv,
		PollInterval: poll, MaxConcurrentSessions: maxSessions,
		Retention: time.Hour, Log: w.log.GetLogger("service"),
	}, w.net)
	require.NoError(t, err)
	return svc
}

// lookupLinked waits until the directory lists the service with n routers.
func (w *world) lookupLinked(t *testing.T, id ps.ServiceID, n int) *ps.ServiceDescriptor {
	t.Helper()
	reader, err := directory.NewClient(w.net, nil, poll)
	require.NoError(t, err)
	var d *ps.ServiceDescriptor
	require.Eventually(t, func() bool {
		var err error
		d, err = reader.Lookup(testCtx(t), id)
		return err == nil && len(d.Routers) == n
	}, 30*time.Second, 50*time.Millisecond)
	return d
}

func echoOnce(t *testing.T, ctx context.Context, s *ps.Session) {
	msg, err := s.Recv(ctx)
	if err != nil {
		return
	}
	_ = s.Send(ctx, append([]byte("echo: "), msg...))
}

func TestServiceEndToEnd(t *testing.T) {
	w := newWorld(t)
	svc := w.service(t, t.TempDir(), 4)
	ctx, cancel := context.WithCancel(testCtx(t))
	defer cancel()
	go svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
		for {
			msg, err := s.Recv(ctx)
			if err != nil {
				return
			}
			if err := s.Send(ctx, append([]byte("echo: "), msg...)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(func() { cancel(); svc.Close() })

	d := w.lookupLinked(t, svc.ID(), 2)
	conn, err := ps.Dial(ctx, w.net, d, "alice", poll)
	require.NoError(t, err)
	for _, m := range []string{"hello", "again"} {
		require.NoError(t, conn.Send(ctx, []byte(m)))
		got, err := conn.Recv(ctx)
		require.NoError(t, err)
		require.Equal(t, "echo: "+m, string(got))
	}
}

// TestServiceOverSlowNetwork runs the docker echo scenario with mixnet-like
// latency: clients dial as soon as the directory lists one router, while
// the service is still linking with the others, and more clients come than
// the service serves at once.
func TestServiceOverSlowNetwork(t *testing.T) {
	w := newWorld(t)
	w.net.Latency = 10 * time.Millisecond
	const limit = 2
	svc := w.service(t, t.TempDir(), limit)
	ctx, cancel := context.WithCancel(testCtx(t))
	defer cancel()
	go svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
		defer s.Close()
		echoOnce(t, ctx, s)
	}))
	t.Cleanup(func() { cancel(); svc.Close() })

	reader, err := directory.NewClient(w.net, nil, poll)
	require.NoError(t, err)
	var d *ps.ServiceDescriptor
	require.Eventually(t, func() bool {
		d, err = reader.Lookup(ctx, svc.ID())
		return err == nil && len(d.Routers) > 0
	}, 30*time.Second, poll)

	const clients = limit + 1
	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := ps.Dial(ctx, w.net, d, "client", poll)
			if err != nil {
				errs <- err
				return
			}
			msg := []byte{byte('a' + i)}
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
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

func TestServiceBoundsConcurrentSessions(t *testing.T) {
	w := newWorld(t)
	const limit = 2
	svc := w.service(t, t.TempDir(), limit)
	ctx, cancel := context.WithCancel(testCtx(t))
	defer cancel()

	var active, peak atomic.Int32
	release := make(chan struct{})
	go svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
		n := active.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		echoOnce(t, ctx, s)
		active.Add(-1)
		_ = s.Close()
	}))
	t.Cleanup(func() { cancel(); svc.Close() })

	d := w.lookupLinked(t, svc.ID(), 2)
	const clients = 5
	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := ps.Dial(ctx, w.net, d, "client", poll)
			if err != nil {
				errs <- err
				return
			}
			msg := []byte{byte('a' + i)}
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
		}()
	}

	require.Eventually(t, func() bool { return active.Load() == limit }, 30*time.Second, 10*time.Millisecond,
		"sessions fill every slot")
	time.Sleep(500 * time.Millisecond)
	require.Equal(t, int32(limit), active.Load(), "the other clients wait for a slot")

	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, int32(limit), peak.Load(), "never more sessions at once than the limit")
}

func TestServiceResumesAfterRestart(t *testing.T) {
	w := newWorld(t)
	dataDir := t.TempDir()
	echo := ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
		for {
			msg, err := s.Recv(ctx)
			if err != nil {
				return
			}
			if err := s.Send(ctx, append([]byte("echo: "), msg...)); err != nil {
				return
			}
		}
	})

	svc := w.service(t, dataDir, 4)
	ctx1, cancel1 := context.WithCancel(testCtx(t))
	done := make(chan struct{})
	go func() { svc.Run(ctx1, echo); close(done) }()

	d := w.lookupLinked(t, svc.ID(), 2)
	ctx := testCtx(t)
	conn, err := ps.Dial(ctx, w.net, d, "alice", poll)
	require.NoError(t, err)
	require.NoError(t, conn.Send(ctx, []byte("one")))
	got, err := conn.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, "echo: one", string(got))

	cancel1()
	<-done
	require.NoError(t, svc.Close())

	// The same service, from the same data directory: links and the
	// session come back without registering or dialling again.
	again := w.service(t, dataDir, 4)
	require.Equal(t, svc.ID(), again.ID())
	ctx2, cancel2 := context.WithCancel(testCtx(t))
	go again.Run(ctx2, echo)
	t.Cleanup(func() { cancel2(); again.Close() })

	require.NoError(t, conn.Send(ctx, []byte("two")))
	got, err = conn.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, "echo: two", string(got))

	// New clients still reach it.
	conn2, err := ps.Dial(ctx, w.net, w.lookupLinked(t, svc.ID(), 2), "bob", poll)
	require.NoError(t, err)
	require.NoError(t, conn2.Send(ctx, []byte("three")))
	got, err = conn2.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, "echo: three", string(got))
}

func TestDialFallsBackToAnotherRouter(t *testing.T) {
	w := newWorld(t)
	svc := w.service(t, t.TempDir(), 4)
	ctx, cancel := context.WithCancel(testCtx(t))
	defer cancel()
	go svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) { echoOnce(t, ctx, s) }))
	t.Cleanup(func() { cancel(); svc.Close() })

	d := w.lookupLinked(t, svc.ID(), 2)
	// Put a router the service never linked with first: it answers
	// UnknownService and Dial moves on.
	unlinked := pluginKey(t)
	r, err := router.New(router.Config{Key: unlinked, DBPath: filepath.Join(t.TempDir(), "r.db"), PollInterval: poll, Log: w.log.GetLogger("r")}, w.net)
	require.NoError(t, err)
	t.Cleanup(func() { r.Close() })
	w.net.AddService("other_router", [32]byte{0xee}, "other_router", nil, func(_ context.Context, p []byte) []byte { return r.Handle(p) })
	d.Routers = append([]ps.RouterRef{{NodeIDHash: [32]byte{0xee}, Endpoint: "other_router"}}, d.Routers...)

	conn, err := ps.Dial(ctx, w.net, d, "carol", poll)
	require.NoError(t, err)
	require.NoError(t, conn.Send(ctx, []byte("hi")))
	got, err := conn.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, "echo: hi", string(got))
}

// TestServiceRetriesAbandonedRegistration has the router accept a
// registration and never induct it, as when its induction times out. The
// service gives up at RegisterTimeout and links on its next rescan.
func TestServiceRetriesAbandonedRegistration(t *testing.T) {
	defer ps.SetRescanInterval(100 * time.Millisecond)()
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	net := phtest.NewNetwork()
	key := pluginKey(t)
	r, err := router.New(router.Config{
		Key: key, DBPath: filepath.Join(t.TempDir(), "router.db"),
		PollInterval: poll, Retention: time.Hour, Log: logBackend.GetLogger("router"),
	}, net)
	require.NoError(t, err)
	t.Cleanup(func() { r.Close() })
	var registers atomic.Int32
	net.AddService(ps.RouterCapability, [32]byte{0xa0}, ps.RouterCapability, ps.PluginParams(key),
		func(_ context.Context, p []byte) []byte {
			var req ps.RouterRequest
			if ps.Unmarshal(p, &req) == nil && req.Register != nil && registers.Add(1) == 1 {
				reply, _ := ps.Marshal(&ps.RouterReply{Status: ps.StatusOK})
				return reply
			}
			return r.Handle(p)
		})

	dataDir := t.TempDir()
	svcKey, err := ps.LoadServiceKey(dataDir)
	require.NoError(t, err)
	svc, err := ps.NewService(ps.Config{
		Key: svcKey, DataDir: dataDir, PollInterval: poll, Retention: time.Hour,
		RegisterTimeout: 3 * time.Second, Log: logBackend.GetLogger("service"),
	}, net)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(testCtx(t))
	go svc.Run(ctx, ps.HandlerFunc(func(context.Context, *ps.Session) {}))
	t.Cleanup(func() { cancel(); svc.Close() })

	require.Eventually(t, func() bool { return len(svc.Descriptor().Routers) == 1 },
		20*time.Second, 50*time.Millisecond)
	require.Equal(t, int32(2), registers.Load())
}
