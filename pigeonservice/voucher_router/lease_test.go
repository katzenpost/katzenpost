// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package voucher_router_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
)

// clock is a settable clock for the router's leases.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func (f *fixture) withClock(t *testing.T) *clock {
	t.Helper()
	c := &clock{t: time.Now()}
	f.router.SetNow(c.now)
	return c
}

func (c *clock) at(d time.Duration) uint64 { return uint64(c.t.Add(d).Unix()) }

func (f *fixture) register(t *testing.T, expiry uint64) *voucher_router.Conn {
	t.Helper()
	ctx := testCtx(t)
	link, err := voucher_router.Register(ctx, f.net, f.svc, &f.node, poll, expiry)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return f.router.Linked(f.svc.ID()) }, 10*time.Second, poll)
	return link
}

func statusOf(t *testing.T, err error) uint8 {
	t.Helper()
	var se *common.StatusError
	require.ErrorAs(t, err, &se)
	return se.Status
}

func TestLinkExpires(t *testing.T) {
	f := newFixture(t)
	c := f.withClock(t)
	ctx := testCtx(t)
	f.register(t, c.at(time.Hour))

	c.t = c.t.Add(2 * time.Hour)
	require.False(t, f.router.Linked(f.svc.ID()))
	require.Equal(t, common.StatusUnknownService, statusOf(t, voucher_router.Route(ctx, f.net, f.descriptor(), bytesOf(1))))
	f.router.Sweep()
	require.Equal(t, 1, f.router.Leases(), "the lease is kept until a replay could no longer be in date")

	c.t = c.t.Add(voucher_router.MaxLinkTTL + common.MaxClockSkew)
	f.router.Sweep()
	require.Equal(t, 0, f.router.Leases())

	f.register(t, c.at(time.Hour))
}

func TestRenewExtendsLink(t *testing.T) {
	f := newFixture(t)
	c := f.withClock(t)
	ctx := testCtx(t)
	link := f.register(t, c.at(time.Hour))

	c.t = c.t.Add(50 * time.Minute)
	require.NoError(t, voucher_router.Renew(ctx, f.net, f.svc, &f.node, c.at(2*time.Hour)))
	c.t = c.t.Add(90 * time.Minute)
	f.router.Sweep()
	require.True(t, f.router.Linked(f.svc.ID()))
	require.NoError(t, voucher_router.Route(ctx, f.net, f.descriptor(), bytesOf(3)))
	got, err := link.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, bytesOf(3), openLinkMessage(t, f.svc, got))

	require.NoError(t, f.router.Close())
	f.startRouter(t)
	f.router.SetNow(c.now)
	require.True(t, f.router.Linked(f.svc.ID()), "the renewed lease is on disk")

	c.t = c.t.Add(time.Hour)
	require.Equal(t, common.StatusUnknownService, statusOf(t, voucher_router.Renew(ctx, f.net, f.svc, &f.node, c.at(time.Hour))), "an expired link is not renewed")
}

func TestUnregister(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	f.register(t, in(time.Hour))

	// An old registration, captured to be replayed later.
	req := &voucher_router.RegisterRequest{NIKEScheme: f.svc.Scheme.Name(), PublicKey: f.svc.Public.Bytes(), Voucher: bytesOf(0x42), Seq: common.NextSeq(), Expiry: in(time.Hour)}
	require.NoError(t, voucher_router.SignRegister(f.svc, f.pk.Public, req))
	replay := mustMarshal(t, &voucher_router.RouterRequest{Register: req})

	require.NoError(t, voucher_router.Unregister(ctx, f.net, f.svc, &f.node))
	require.False(t, f.router.Linked(f.svc.ID()))
	require.Equal(t, common.StatusUnknownService, statusOf(t, voucher_router.Route(ctx, f.net, f.descriptor(), bytesOf(1))))
	require.Equal(t, common.StatusStale, f.handleStatus(t, replay), "a replayed earlier registration does not reopen the link")
	require.Equal(t, common.StatusUnknownService, statusOf(t, voucher_router.Renew(ctx, f.net, f.svc, &f.node, in(time.Hour))))

	f.net.Repeat = 2
	require.NoError(t, voucher_router.Unregister(ctx, f.net, f.svc, &f.node), "a retransmitted unregistration is acknowledged")
	f.net.Repeat = 1

	link := f.register(t, in(time.Hour))
	require.NoError(t, voucher_router.Route(ctx, f.net, f.descriptor(), bytesOf(2)))
	got, err := link.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, bytesOf(2), openLinkMessage(t, f.svc, got))
}

func TestLeaseWindow(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	for _, expiry := range []uint64{0, in(-time.Minute), in(voucher_router.MaxLinkTTL + common.MaxClockSkew + time.Minute)} {
		_, err := voucher_router.Register(ctx, f.net, f.svc, &f.node, poll, expiry)
		require.Equal(t, common.StatusInvalidRequest, statusOf(t, err), "expiry %d", expiry)
	}
	f.register(t, in(voucher_router.MaxLinkTTL))
	require.Equal(t, common.StatusInvalidRequest, statusOf(t, voucher_router.Renew(ctx, f.net, f.svc, &f.node, 0)))
}

func TestMaxLinks(t *testing.T) {
	f := newTunedFixture(t, func(c *voucher_router.Config) { c.MaxLinks = 1 })
	c := f.withClock(t)
	ctx := testCtx(t)
	f.register(t, c.at(time.Hour))
	f.register(t, c.at(time.Hour)) // the same service again is not a second link

	other, _ := newKey(t)
	_, err := voucher_router.Register(ctx, f.net, other, &f.node, poll, c.at(time.Hour))
	require.Equal(t, common.StatusBusy, statusOf(t, err))

	c.t = c.t.Add(2 * time.Hour)
	f.router.Sweep()
	_, err = voucher_router.Register(ctx, f.net, other, &f.node, poll, c.at(time.Hour))
	require.NoError(t, err, "an expired link frees its slot")
}
