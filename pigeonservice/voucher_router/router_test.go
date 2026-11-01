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

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/common/phtest"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
)

const poll = 10 * time.Millisecond

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func newKey(t *testing.T) (*common.ServiceKey, *common.PluginKey) {
	t.Helper()
	pub, priv, err := common.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	ppub, ppriv, err := common.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	return &common.ServiceKey{Scheme: common.DefaultNIKE, Public: pub, Private: priv},
		&common.PluginKey{Scheme: common.DefaultNIKE, Public: ppub, Private: ppriv}
}

type fixture struct {
	net    *phtest.Network
	router *voucher_router.Router
	node   common.ServiceNode
	svc    *common.ServiceKey
	pk     *common.PluginKey
	dbPath string
	tune   func(*voucher_router.Config)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newTunedFixture(t, nil)
}

func newTunedFixture(t *testing.T, tune func(*voucher_router.Config)) *fixture {
	t.Helper()
	net := phtest.NewNetwork()
	svc, pk := newKey(t)
	f := &fixture{net: net, svc: svc, pk: pk, dbPath: filepath.Join(t.TempDir(), "router.db"), tune: tune}
	f.startRouter(t)
	node := [32]byte{0xaa}
	net.AddService(voucher_router.RouterCapability, node, voucher_router.RouterCapability, common.PluginParams(pk),
		func(_ context.Context, payload []byte) []byte { return f.router.Handle(payload) })
	nodes, err := net.Services(voucher_router.RouterCapability)
	require.NoError(t, err)
	f.node = nodes[0]
	return f
}

func (f *fixture) startRouter(t *testing.T) {
	t.Helper()
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	cfg := voucher_router.Config{
		Key:          f.pk,
		DBPath:       f.dbPath,
		PollInterval: poll,
		Retention:    time.Hour,
		Log:          logBackend.GetLogger("router"),
	}
	if f.tune != nil {
		f.tune(&cfg)
	}
	r, err := voucher_router.New(cfg, f.net)
	require.NoError(t, err)
	f.router = r
	t.Cleanup(func() { r.Close() })
}

func (f *fixture) descriptor() *common.ServiceDescriptor {
	return &common.ServiceDescriptor{
		NIKEScheme: f.svc.Scheme.Name(),
		PublicKey:  f.svc.Public.Bytes(),
		Routers:    []common.RouterRef{{NodeIDHash: f.node.NodeIDHash, Endpoint: string(f.node.Endpoint)}},
	}
}

func openLinkMessage(t *testing.T, svc *common.ServiceKey, msg []byte) []byte {
	t.Helper()
	var lm voucher_router.LinkMessage
	require.NoError(t, common.Unmarshal(msg, &lm))
	v, err := sealedbox.NewScheme(svc.Scheme).Open(svc.Private, svc.Public, lm.Forward)
	require.NoError(t, err)
	return v
}

func TestRegisterAndRoute(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)

	link, err := voucher_router.Register(ctx, f.net, f.svc, &f.node, poll)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return f.router.Linked(f.svc.ID()) }, 10*time.Second, poll)

	for _, v := range [][]byte{bytesOf(1), bytesOf(2)} {
		require.NoError(t, voucher_router.Route(ctx, f.net, f.descriptor(), v))
		got, err := link.Recv(ctx)
		require.NoError(t, err)
		require.Equal(t, v, openLinkMessage(t, f.svc, got))
	}
}

// TestRouteWhileInducting routes to a service that has seen its link open
// but whose router is still finishing the induction: the voucher is held
// and written once the link is installed.
func TestRouteWhileInducting(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	f.net.TombstoneGate = make(chan struct{})

	link, err := voucher_router.Register(ctx, f.net, f.svc, &f.node, poll)
	require.NoError(t, err)
	require.False(t, f.router.Linked(f.svc.ID()))

	require.NoError(t, voucher_router.Route(ctx, f.net, f.descriptor(), bytesOf(5)))
	close(f.net.TombstoneGate)

	got, err := link.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, bytesOf(5), openLinkMessage(t, f.svc, got))
	require.True(t, f.router.Linked(f.svc.ID()))
}

func TestRetransmittedRouteIsForwardedOnce(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	link, err := voucher_router.Register(ctx, f.net, f.svc, &f.node, poll)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return f.router.Linked(f.svc.ID()) }, 10*time.Second, poll)

	f.net.Repeat = 3
	require.NoError(t, voucher_router.Route(ctx, f.net, f.descriptor(), bytesOf(7)))
	f.net.Repeat = 1
	require.NoError(t, voucher_router.Route(ctx, f.net, f.descriptor(), bytesOf(8)))

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
	link, err := voucher_router.Register(testCtx(t), f.net, f.svc, &f.node, poll)
	require.NoError(t, err)
	require.NotNil(t, link)
	require.Eventually(t, func() bool { return f.router.Linked(f.svc.ID()) }, 10*time.Second, poll)
}

func TestRouteToUnknownService(t *testing.T) {
	f := newFixture(t)
	err := voucher_router.Route(testCtx(t), f.net, f.descriptor(), bytesOf(1))
	var se *common.StatusError
	require.ErrorAs(t, err, &se)
	require.Equal(t, common.StatusUnknownService, se.Status)
}

func TestRegisterWithBadMAC(t *testing.T) {
	f := newFixture(t)
	req := &voucher_router.RegisterRequest{NIKEScheme: f.svc.Scheme.Name(), PublicKey: f.svc.Public.Bytes(), Voucher: bytesOf(1), MAC: make([]byte, 32)}
	payload, err := common.Marshal(&voucher_router.RouterRequest{Register: req})
	require.NoError(t, err)
	var reply voucher_router.RouterReply
	require.NoError(t, common.Unmarshal(f.router.Handle(payload), &reply))
	require.Equal(t, common.StatusBadMAC, reply.Status)
}

func TestMalformedRequests(t *testing.T) {
	f := newFixture(t)
	for _, payload := range [][]byte{
		nil,
		[]byte("not cbor"),
		mustMarshal(t, &voucher_router.RouterRequest{}),
		mustMarshal(t, &voucher_router.RouterRequest{Route: &voucher_router.RouteRequest{}, Register: &voucher_router.RegisterRequest{}}),
		mustMarshal(t, &voucher_router.RouterRequest{Route: &voucher_router.RouteRequest{}}),
	} {
		var reply voucher_router.RouterReply
		require.NoError(t, common.Unmarshal(f.router.Handle(payload), &reply))
		require.Equal(t, common.StatusInvalidRequest, reply.Status)
	}
}

func TestLinksSurviveRestart(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	link, err := voucher_router.Register(ctx, f.net, f.svc, &f.node, poll)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return f.router.Linked(f.svc.ID()) }, 10*time.Second, poll)
	require.NoError(t, voucher_router.Route(ctx, f.net, f.descriptor(), bytesOf(1)))
	got, err := link.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, bytesOf(1), openLinkMessage(t, f.svc, got))

	require.NoError(t, f.router.Close())
	f.startRouter(t)
	require.True(t, f.router.Linked(f.svc.ID()))

	require.NoError(t, voucher_router.Route(ctx, f.net, f.descriptor(), bytesOf(2)))
	got, err = link.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, bytesOf(2), openLinkMessage(t, f.svc, got), "the restarted router resumes the link where it left off")
}

// stalledRegistrations returns correctly signed registrations of n
// vouchers whose contact boxes are never written.
func (f *fixture) stalledRegistrations(t *testing.T, n int) [][]byte {
	t.Helper()
	payloads := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range payloads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &voucher_router.RegisterRequest{NIKEScheme: f.svc.Scheme.Name(), PublicKey: f.svc.Public.Bytes(), Voucher: bytesOf(byte(0x80 + i))}
			if errs[i] = voucher_router.SignRegister(f.svc, f.pk.Public, req); errs[i] == nil {
				payloads[i], errs[i] = common.Marshal(&voucher_router.RouterRequest{Register: req})
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	return payloads
}

func (f *fixture) handleStatus(t *testing.T, payload []byte) uint8 {
	t.Helper()
	var reply voucher_router.RouterReply
	require.NoError(t, common.Unmarshal(f.router.Handle(payload), &reply))
	return reply.Status
}

// TestStalledRegistrationsAreBounded sends many registrations that never
// complete. The router inducts at most MaxInductions at once and refuses
// the rest as busy, so they hold no goroutine or pending state.
func TestStalledRegistrationsAreBounded(t *testing.T) {
	const limit = 3
	f := newTunedFixture(t, func(cfg *voucher_router.Config) {
		cfg.MaxInductions = limit
		cfg.InductTimeout = time.Hour
	})
	payloads := f.stalledRegistrations(t, 12)

	for i, payload := range payloads {
		want := common.StatusOK
		if i >= limit {
			want = common.StatusBusy
		}
		require.Equal(t, want, f.handleStatus(t, payload), "registration %d", i)
	}
	registering, pending := f.router.Inductions()
	require.Equal(t, limit, registering)
	require.Equal(t, 1, pending)
	require.Equal(t, common.StatusOK, f.handleStatus(t, payloads[0]), "a retransmission is not refused")
}

// TestStalledRegistrationsTimeOut checks that a registration that never
// completes is abandoned at InductTimeout, freeing its slot and its
// pending queue for the next registration.
func TestStalledRegistrationsTimeOut(t *testing.T) {
	const limit = 2
	f := newTunedFixture(t, func(cfg *voucher_router.Config) {
		cfg.MaxInductions = limit
		cfg.InductTimeout = 200 * time.Millisecond
	})
	payloads := f.stalledRegistrations(t, limit+1)
	for _, payload := range payloads[:limit] {
		require.Equal(t, common.StatusOK, f.handleStatus(t, payload))
	}

	require.Eventually(t, func() bool {
		registering, pending := f.router.Inductions()
		return registering == 0 && pending == 0
	}, 10*time.Second, poll, "stalled inductions are abandoned at their deadline")
	require.Equal(t, common.StatusOK, f.handleStatus(t, payloads[limit]), "the freed slots admit a new registration")
}

// TestCompletedRegistrationIsReleased checks that a successful induction
// gives up its slot, while a retransmission of it is still acknowledged
// without a second induction.
func TestCompletedRegistrationIsReleased(t *testing.T) {
	f := newTunedFixture(t, func(cfg *voucher_router.Config) { cfg.MaxInductions = 1 })
	ctx := testCtx(t)
	f.net.Repeat = 3
	_, err := voucher_router.Register(ctx, f.net, f.svc, &f.node, poll)
	require.NoError(t, err)
	f.net.Repeat = 1
	require.Eventually(t, func() bool {
		registering, pending := f.router.Inductions()
		return f.router.Linked(f.svc.ID()) && registering == 0 && pending == 0
	}, 10*time.Second, poll)

	other, _ := newKey(t)
	_, err = voucher_router.Register(ctx, f.net, other, &f.node, poll)
	require.NoError(t, err, "the released slot admits the next registration")
	require.Eventually(t, func() bool { return f.router.Linked(other.ID()) }, 10*time.Second, poll)
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
	b, err := common.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestLinkBacklogIsBounded(t *testing.T) {
	f := newTunedFixture(t, func(c *voucher_router.Config) { c.MaxRetained = 2 })
	ctx := testCtx(t)
	_, err := voucher_router.Register(ctx, f.net, f.svc, &f.node, poll)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return f.router.Linked(f.svc.ID()) }, 10*time.Second, poll)

	require.NoError(t, voucher_router.Route(ctx, f.net, f.descriptor(), bytesOf(1)))
	require.NoError(t, voucher_router.Route(ctx, f.net, f.descriptor(), bytesOf(2)))
	var se *common.StatusError
	require.ErrorAs(t, voucher_router.Route(ctx, f.net, f.descriptor(), bytesOf(3)), &se)
	require.Equal(t, common.StatusBusy, se.Status)
}

// TestReregistrationTakesOverRouting has a service that lost its link
// register again: vouchers routed while the new link is inducted go to it,
// not to the old link nobody reads.
func TestReregistrationTakesOverRouting(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	_, err := voucher_router.Register(ctx, f.net, f.svc, &f.node, poll)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return f.router.Linked(f.svc.ID()) }, 10*time.Second, poll)

	f.net.TombstoneGate = make(chan struct{})
	link, err := voucher_router.Register(ctx, f.net, f.svc, &f.node, poll)
	require.NoError(t, err)
	require.NoError(t, voucher_router.Route(ctx, f.net, f.descriptor(), bytesOf(9)))
	close(f.net.TombstoneGate)

	got, err := link.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, bytesOf(9), openLinkMessage(t, f.svc, got))
}
