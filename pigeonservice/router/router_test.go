// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package router_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/protocols/box"

	"github.com/katzenpost/katzenpost/core/log"
	ps "github.com/katzenpost/katzenpost/pigeonservice"
	"github.com/katzenpost/katzenpost/pigeonservice/phtest"
	"github.com/katzenpost/katzenpost/pigeonservice/router"
)

const poll = 10 * time.Millisecond

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func newKey(t *testing.T) (*ps.ServiceKey, *ps.PluginKey) {
	t.Helper()
	pub, priv, err := ps.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	ppub, ppriv, err := ps.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	return &ps.ServiceKey{Scheme: ps.DefaultNIKE, Public: pub, Private: priv},
		&ps.PluginKey{Scheme: ps.DefaultNIKE, Public: ppub, Private: ppriv}
}

type fixture struct {
	net    *phtest.Network
	router *router.Router
	node   ps.ServiceNode
	svc    *ps.ServiceKey
	pk     *ps.PluginKey
	dbPath string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	net := phtest.NewNetwork()
	svc, pk := newKey(t)
	f := &fixture{net: net, svc: svc, pk: pk, dbPath: filepath.Join(t.TempDir(), "router.db")}
	f.startRouter(t)
	node := [32]byte{0xaa}
	net.AddService(ps.RouterCapability, node, ps.RouterCapability, ps.PluginParams(pk),
		func(_ context.Context, payload []byte) []byte { return f.router.Handle(payload) })
	nodes, err := net.Services(ps.RouterCapability)
	require.NoError(t, err)
	f.node = nodes[0]
	return f
}

func (f *fixture) startRouter(t *testing.T) {
	t.Helper()
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	r, err := router.New(router.Config{
		Key:          f.pk,
		DBPath:       f.dbPath,
		PollInterval: poll,
		Retention:    time.Hour,
		Log:          logBackend.GetLogger("router"),
	}, f.net)
	require.NoError(t, err)
	f.router = r
	t.Cleanup(func() { r.Close() })
}

func (f *fixture) descriptor() *ps.ServiceDescriptor {
	return &ps.ServiceDescriptor{
		NIKEScheme: f.svc.Scheme.Name(),
		PublicKey:  f.svc.Public.Bytes(),
		Routers:    []ps.RouterRef{{NodeIDHash: f.node.NodeIDHash, Endpoint: string(f.node.Endpoint)}},
	}
}

func openLinkMessage(t *testing.T, svc *ps.ServiceKey, msg []byte) []byte {
	t.Helper()
	var lm ps.LinkMessage
	require.NoError(t, ps.Unmarshal(msg, &lm))
	v, err := box.NewScheme(svc.Scheme).Open(svc.Private, svc.Public, lm.Forward)
	require.NoError(t, err)
	return v
}

func TestRegisterAndRoute(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)

	link, err := ps.Register(ctx, f.net, f.svc, &f.node, poll)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return f.router.Linked(f.svc.ID()) }, 10*time.Second, poll)

	for _, v := range [][]byte{bytesOf(1), bytesOf(2)} {
		require.NoError(t, ps.Route(ctx, f.net, f.descriptor(), v))
		got, err := link.Recv(ctx)
		require.NoError(t, err)
		require.Equal(t, v, openLinkMessage(t, f.svc, got))
	}
}

func TestRetransmittedRouteIsForwardedOnce(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	link, err := ps.Register(ctx, f.net, f.svc, &f.node, poll)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return f.router.Linked(f.svc.ID()) }, 10*time.Second, poll)

	f.net.Repeat = 3
	require.NoError(t, ps.Route(ctx, f.net, f.descriptor(), bytesOf(7)))
	f.net.Repeat = 1
	require.NoError(t, ps.Route(ctx, f.net, f.descriptor(), bytesOf(8)))

	got, err := link.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, bytesOf(7), openLinkMessage(t, f.svc, got))
	got, err = link.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, bytesOf(8), openLinkMessage(t, f.svc, got), "the repeats were not forwarded")
}

func TestRetransmittedRegisterInductsOnce(t *testing.T) {
	f := newFixture(t)
	f.net.Repeat = 3
	link, err := ps.Register(testCtx(t), f.net, f.svc, &f.node, poll)
	require.NoError(t, err)
	require.NotNil(t, link)
	require.Eventually(t, func() bool { return f.router.Linked(f.svc.ID()) }, 10*time.Second, poll)
}

func TestRouteToUnknownService(t *testing.T) {
	f := newFixture(t)
	err := ps.Route(testCtx(t), f.net, f.descriptor(), bytesOf(1))
	var se *ps.StatusError
	require.ErrorAs(t, err, &se)
	require.Equal(t, ps.StatusUnknownService, se.Status)
}

func TestRegisterWithBadMAC(t *testing.T) {
	f := newFixture(t)
	req := &ps.RegisterRequest{NIKEScheme: f.svc.Scheme.Name(), PublicKey: f.svc.Public.Bytes(), Voucher: bytesOf(1), MAC: make([]byte, 32)}
	payload, err := ps.Marshal(&ps.RouterRequest{Register: req})
	require.NoError(t, err)
	var reply ps.RouterReply
	require.NoError(t, ps.Unmarshal(f.router.Handle(payload), &reply))
	require.Equal(t, ps.StatusBadMAC, reply.Status)
}

func TestMalformedRequests(t *testing.T) {
	f := newFixture(t)
	for _, payload := range [][]byte{
		nil,
		[]byte("not cbor"),
		mustMarshal(t, &ps.RouterRequest{}),
		mustMarshal(t, &ps.RouterRequest{Route: &ps.RouteRequest{}, Register: &ps.RegisterRequest{}}),
		mustMarshal(t, &ps.RouterRequest{Route: &ps.RouteRequest{}}),
	} {
		var reply ps.RouterReply
		require.NoError(t, ps.Unmarshal(f.router.Handle(payload), &reply))
		require.Equal(t, ps.StatusInvalidRequest, reply.Status)
	}
}

func TestLinksSurviveRestart(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	link, err := ps.Register(ctx, f.net, f.svc, &f.node, poll)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return f.router.Linked(f.svc.ID()) }, 10*time.Second, poll)
	require.NoError(t, ps.Route(ctx, f.net, f.descriptor(), bytesOf(1)))
	got, err := link.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, bytesOf(1), openLinkMessage(t, f.svc, got))

	require.NoError(t, f.router.Close())
	f.startRouter(t)
	require.True(t, f.router.Linked(f.svc.ID()))

	require.NoError(t, ps.Route(ctx, f.net, f.descriptor(), bytesOf(2)))
	got, err = link.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, bytesOf(2), openLinkMessage(t, f.svc, got), "the restarted router resumes the link where it left off")
}

func bytesOf(b byte) []byte {
	v := make([]byte, 32)
	for i := range v {
		v[i] = b
	}
	return v
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := ps.Marshal(v)
	require.NoError(t, err)
	return b
}
