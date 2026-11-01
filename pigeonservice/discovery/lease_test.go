// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package discovery_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time            { return c.t }
func (c *clock) at(d time.Duration) uint64 { return uint64(c.t.Add(d).Unix()) }

func (f *fixture) withClock(t *testing.T) *clock {
	t.Helper()
	c := &clock{t: time.Now()}
	f.dir.SetNow(c.now)
	return c
}

func statusOf(t *testing.T, err error) uint8 {
	t.Helper()
	var se *common.StatusError
	require.ErrorAs(t, err, &se)
	return se.Status
}

func TestEntryExpires(t *testing.T) {
	f := newFixture(t)
	c := f.withClock(t)
	ctx := testCtx(t)
	k := serviceKey(t)
	granted, err := f.client(t, k).Advertise(ctx, descriptor(k, 1), c.at(time.Hour))
	require.NoError(t, err)
	require.Equal(t, c.at(time.Hour), granted)
	listEventually(t, f.client(t, nil), 1)

	c.t = c.t.Add(2 * time.Hour)
	_, err = f.client(t, nil).Lookup(ctx, k.ID())
	require.Equal(t, common.StatusUnknownService, statusOf(t, err))
	f.dir.Republish()
	listEventually(t, f.client(t, nil), 0)
	require.Equal(t, 1, f.dir.Entries(), "the entry is kept until a replay could no longer be in date")

	c.t = c.t.Add(discovery.MaxEntryTTL + common.MaxClockSkew)
	f.dir.Republish()
	require.Eventually(t, func() bool { return f.dir.Entries() == 0 }, 10*time.Second, poll)
}

func TestReadvertiseRenews(t *testing.T) {
	f := newFixture(t)
	c := f.withClock(t)
	ctx := testCtx(t)
	k := serviceKey(t)
	cl := f.client(t, k)
	_, err := cl.Advertise(ctx, descriptor(k, 1), c.at(time.Hour))
	require.NoError(t, err)
	c.t = c.t.Add(50 * time.Minute)
	_, err = cl.Advertise(ctx, descriptor(k, 1), c.at(2*time.Hour))
	require.NoError(t, err)
	c.t = c.t.Add(90 * time.Minute)
	got, err := f.client(t, nil).Lookup(ctx, k.ID())
	require.NoError(t, err)
	require.Len(t, got.Routers, 1)
}

func TestLeaseWindow(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	k := serviceKey(t)
	for _, expiry := range []uint64{0, in(-time.Minute), in(discovery.MaxEntryTTL + common.MaxClockSkew + time.Minute)} {
		_, err := f.client(t, k).Advertise(ctx, descriptor(k, 1), expiry)
		require.Equal(t, common.StatusInvalidRequest, statusOf(t, err), "expiry %d", expiry)
	}
	_, err := f.client(t, k).Advertise(ctx, descriptor(k, 1), in(discovery.MaxEntryTTL))
	require.NoError(t, err)
}

func TestMaxEntries(t *testing.T) {
	f := newFixture(t)
	f.dir.Close()
	f.tune = func(c *discovery.Config) { c.MaxEntries = 1 }
	f.start(t)
	c := f.withClock(t)
	ctx := testCtx(t)
	a, b := serviceKey(t), serviceKey(t)
	_, err := f.client(t, a).Advertise(ctx, descriptor(a, 1), c.at(time.Hour))
	require.NoError(t, err)
	_, err = f.client(t, a).Advertise(ctx, descriptor(a, 2), c.at(time.Hour))
	require.NoError(t, err, "the same service again is not a second entry")
	_, err = f.client(t, b).Advertise(ctx, descriptor(b, 1), c.at(time.Hour))
	require.Equal(t, common.StatusBusy, statusOf(t, err))

	c.t = c.t.Add(2 * time.Hour)
	_, err = f.client(t, b).Advertise(ctx, descriptor(b, 1), c.at(time.Hour))
	require.NoError(t, err, "an expired entry frees its slot")
}

// TestReplayAfterPurge replays an advertisement after the directory has
// forgotten the service that withdrew it: the advertisement is out of date
// by then, so it cannot bring the descriptor back.
func TestReplayAfterPurge(t *testing.T) {
	f := newFixture(t)
	c := f.withClock(t)
	k := serviceKey(t)
	adv := &discovery.AdvertiseRequest{Descriptor: *descriptor(k, 1), Seq: 10, Expiry: c.at(discovery.MaxEntryTTL)}
	require.NoError(t, discovery.SignAdvertise(k, f.pk.Public, adv))
	require.Equal(t, common.StatusOK, handle(t, f, &discovery.DirectoryRequest{Advertise: adv}).Status)
	wd := &discovery.WithdrawRequest{ServiceID: k.ID(), Seq: 11}
	require.NoError(t, discovery.SignWithdraw(k, f.pk.Public, wd))
	require.Equal(t, common.StatusOK, handle(t, f, &discovery.DirectoryRequest{Withdraw: wd}).Status)
	require.Equal(t, common.StatusStale, handle(t, f, &discovery.DirectoryRequest{Advertise: adv}).Status)

	c.t = c.t.Add(discovery.MaxEntryTTL + common.MaxClockSkew + time.Second)
	f.dir.Republish()
	require.Eventually(t, func() bool { return f.dir.Entries() == 0 }, 10*time.Second, poll)
	require.Equal(t, common.StatusInvalidRequest, handle(t, f, &discovery.DirectoryRequest{Advertise: adv}).Status)
	_, err := f.client(t, nil).Lookup(testCtx(t), k.ID())
	require.Equal(t, common.StatusUnknownService, statusOf(t, err))
}
