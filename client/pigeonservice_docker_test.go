//go:build docker_test

// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/protocols/sealedbox"

	"github.com/katzenpost/katzenpost/core/log"
	ps "github.com/katzenpost/katzenpost/pigeonservice"
	"github.com/katzenpost/katzenpost/pigeonservice/directory"
)

// The pigeonservice end-to-end tests run against the voucher routers and
// service directories genconfig puts on every service node of the docker
// mixnet. They take minutes: every step is one or more Pigeonhole round
// trips through the mixnet.

const (
	// pigeonserviceTimeout stays well inside the suite's go test timeout,
	// so a stalled step fails with its own error instead of a panic.
	pigeonserviceTimeout = 20 * time.Minute
	pigeonservicePoll    = 5 * time.Second
)

func pigeonserviceCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), pigeonserviceTimeout)
	t.Cleanup(cancel)
	return ctx
}

func pigeonserviceThin(t *testing.T) ps.Pigeonhole {
	c := setupThinClient(t)
	t.Cleanup(func() { c.Close() })
	return ps.NewThinPigeonhole(c)
}

func newServiceKey(t *testing.T) *ps.ServiceKey {
	key, err := ps.LoadServiceKey(t.TempDir())
	require.NoError(t, err)
	return key
}

// TestPigeonServicePlainARQ sends a payload to the echo kaetzchen with the
// plain ARQ and gets it back.
func TestPigeonServicePlainARQ(t *testing.T) {
	c := setupThinClient(t)
	t.Cleanup(func() { c.Close() })
	svc, err := c.GetService("echo")
	require.NoError(t, err)
	node := hash.Sum256(svc.MixDescriptor.IdentityKey)

	ctx := pigeonserviceCtx(t)
	for _, payload := range [][]byte{[]byte("plain ARQ one"), []byte("plain ARQ two")} {
		reply, err := c.StartResendingMessage(ctx, &node, svc.RecipientQueueID, payload)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(reply), len(payload))
		require.Equal(t, payload, reply[:len(payload)])
	}
}

// TestPigeonServiceDirectory advertises a descriptor to every directory,
// looks it up, finds it in the snapshot stream, and checks that a forged
// advertisement is refused.
func TestPigeonServiceDirectory(t *testing.T) {
	skipInShortMode(t)
	ph := pigeonserviceThin(t)
	ctx := pigeonserviceCtx(t)
	key := newServiceKey(t)

	adv, err := directory.NewAll(ph, key, pigeonservicePoll)
	require.NoError(t, err)
	d := &ps.ServiceDescriptor{
		NIKEScheme: key.Scheme.Name(),
		PublicKey:  key.Public.Bytes(),
		Routers:    []ps.RouterRef{{NodeIDHash: [32]byte{1}, Endpoint: ps.RouterCapability}},
	}
	require.NoError(t, adv.Advertise(ctx, d))

	reader, err := directory.NewAll(ph, nil, pigeonservicePoll)
	require.NoError(t, err)
	got, err := reader.Lookup(ctx, key.ID())
	require.NoError(t, err)
	require.Equal(t, d, got)

	listed := false
	for !listed {
		all, err := reader.List(ctx)
		require.NoError(t, err)
		for _, x := range all {
			listed = listed || x.ID() == key.ID()
		}
		if !listed {
			t.Log("the snapshot does not list the service yet")
			time.Sleep(10 * time.Second)
		}
	}

	nodes, err := ph.Services(ps.DirectoryCapability)
	require.NoError(t, err)
	mallory := newServiceKey(t)
	dirPub, err := ps.PluginPublicKey(&nodes[0], ps.DefaultNIKE)
	require.NoError(t, err)
	forged := &ps.AdvertiseRequest{Descriptor: *d, Seq: uint64(time.Now().UnixNano())}
	require.NoError(t, mallory.SignAdvertise(dirPub, forged))
	payload, err := ps.Marshal(&ps.DirectoryRequest{Advertise: forged})
	require.NoError(t, err)
	raw, err := ph.Request(ctx, &nodes[0].NodeIDHash, nodes[0].Endpoint, payload)
	require.NoError(t, err)
	var reply ps.DirectoryReply
	require.NoError(t, ps.Unmarshal(raw, &reply))
	require.Equal(t, ps.StatusBadMAC, reply.Status)
}

// TestPigeonServiceRouter registers a service with a voucher router, routes
// a sealed voucher through it, and reads it off the link.
func TestPigeonServiceRouter(t *testing.T) {
	skipInShortMode(t)
	ph := pigeonserviceThin(t)
	ctx := pigeonserviceCtx(t)
	key := newServiceKey(t)

	nodes, err := ph.Services(ps.RouterCapability)
	require.NoError(t, err)
	require.NotEmpty(t, nodes, "the PKI lists a voucher router")
	node := nodes[0]

	link, err := ps.Register(ctx, ph, key, &node, pigeonservicePoll)
	require.NoError(t, err)

	d := &ps.ServiceDescriptor{
		NIKEScheme: key.Scheme.Name(),
		PublicKey:  key.Public.Bytes(),
		Routers:    []ps.RouterRef{{NodeIDHash: node.NodeIDHash, Endpoint: string(node.Endpoint)}},
	}
	voucher := make([]byte, 32)
	copy(voucher, "a voucher for the docker mixnet")
	require.NoError(t, ps.Route(ctx, ph, d, voucher))

	msg, err := link.Recv(ctx)
	require.NoError(t, err)
	var lm ps.LinkMessage
	require.NoError(t, ps.Unmarshal(msg, &lm))
	opened, err := sealedbox.NewScheme(key.Scheme).Open(key.Private, key.Public, lm.Forward)
	require.NoError(t, err)
	require.Equal(t, voucher, opened)
}

// TestPigeonServiceEcho runs an echo service on one thin connection and
// talks to it from others: through the directory, a voucher router, and
// the contact voucher handshake, more clients at once than the service
// serves concurrently.
func TestPigeonServiceEcho(t *testing.T) {
	skipInShortMode(t)
	ctx := pigeonserviceCtx(t)
	logBackend, err := log.New("", defaultTestLogLevel, false)
	require.NoError(t, err)

	servicePh := pigeonserviceThin(t)
	dataDir := t.TempDir()
	key, err := ps.LoadServiceKey(dataDir)
	require.NoError(t, err)
	adv, err := directory.NewAll(servicePh, key, pigeonservicePoll)
	require.NoError(t, err)
	const limit = 2
	svc, err := ps.NewService(ps.Config{
		Key:                   key,
		DataDir:               dataDir,
		DisplayName:           "echo",
		Advertiser:            adv,
		PollInterval:          pigeonservicePoll,
		MaxConcurrentSessions: limit,
		Log:                   logBackend.GetLogger("echo"),
	}, servicePh)
	require.NoError(t, err)
	svcCtx, stop := context.WithCancel(ctx)
	go svc.Run(svcCtx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
		defer s.Close()
		msg, err := s.Recv(ctx)
		if err != nil {
			return
		}
		_ = s.Send(ctx, append([]byte("echo: "), msg...))
	}))
	t.Cleanup(func() { stop(); svc.Close() })

	clientPh := pigeonserviceThin(t)
	reader, err := directory.NewAll(clientPh, nil, pigeonservicePoll)
	require.NoError(t, err)
	var d *ps.ServiceDescriptor
	for {
		d, err = reader.Lookup(ctx, svc.ID())
		if err == nil && len(d.Routers) > 0 {
			break
		}
		require.NoError(t, ctx.Err())
		t.Logf("the service has not advertised a router yet: %v", err)
		time.Sleep(10 * time.Second)
	}
	t.Logf("the directory lists the service with %d routers", len(d.Routers))

	const clients = limit + 1
	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := ps.Dial(ctx, clientPh, d, "client", pigeonservicePoll)
			if err != nil {
				errs <- fmt.Errorf("client %d: dial: %w", i, err)
				return
			}
			t.Logf("client %d: connected", i)
			msg := []byte{'h', 'i', ' ', byte('a' + i)}
			if err := conn.Send(ctx, msg); err != nil {
				errs <- fmt.Errorf("client %d: send: %w", i, err)
				return
			}
			reply, err := conn.Recv(ctx)
			if err != nil {
				errs <- fmt.Errorf("client %d: receive: %w", i, err)
				return
			}
			t.Logf("client %d: echoed", i)
			if string(reply) != "echo: "+string(msg) {
				errs <- &unexpectedReply{got: string(reply)}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

type unexpectedReply struct{ got string }

func (e *unexpectedReply) Error() string { return "unexpected reply: " + e.got }
