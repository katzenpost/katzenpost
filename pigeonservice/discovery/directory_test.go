// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package discovery_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/common/phtest"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
)

const poll = 10 * time.Millisecond

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func serviceKey(t *testing.T) *common.ServiceKey {
	t.Helper()
	pub, priv, err := common.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	return &common.ServiceKey{Scheme: common.DefaultNIKE, Public: pub, Private: priv}
}

type fixture struct {
	net    *phtest.Network
	dir    *discovery.Directory
	pk     *common.PluginKey
	dbPath string
	tune   func(*discovery.Config)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := common.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	f := &fixture{
		net:    phtest.NewNetwork(),
		pk:     &common.PluginKey{Scheme: common.DefaultNIKE, Public: pub, Private: priv},
		dbPath: filepath.Join(t.TempDir(), "directory.db"),
	}
	f.net.MaxBox = 200 // small boxes, so a snapshot spans several
	f.start(t)
	f.net.AddService(discovery.DirectoryCapability, [32]byte{0xdd}, discovery.DirectoryCapability, common.PluginParams(f.pk),
		func(_ context.Context, payload []byte) []byte { return f.dir.Handle(payload) })
	return f
}

func (f *fixture) start(t *testing.T) {
	t.Helper()
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	cfg := discovery.Config{
		Key:             f.pk,
		DBPath:          f.dbPath,
		RefreshInterval: time.Hour,
		Log:             logBackend.GetLogger("directory"),
	}
	if f.tune != nil {
		f.tune(&cfg)
	}
	d, err := discovery.New(cfg, f.net)
	require.NoError(t, err)
	f.dir = d
	t.Cleanup(func() { d.Close() })
}

func (f *fixture) client(t *testing.T, key *common.ServiceKey) *discovery.Client {
	t.Helper()
	c, err := discovery.NewClient(f.net, key, poll)
	require.NoError(t, err)
	return c
}

func descriptor(key *common.ServiceKey, routers int) *common.ServiceDescriptor {
	d := &common.ServiceDescriptor{NIKEScheme: key.Scheme.Name(), PublicKey: key.Public.Bytes()}
	for i := range routers {
		d.Routers = append(d.Routers, common.RouterRef{NodeIDHash: [32]byte{byte(i)}, Endpoint: voucher_router.RouterCapability})
	}
	return d
}

func listEventually(t *testing.T, c *discovery.Client, n int) []common.ServiceDescriptor {
	t.Helper()
	var got []common.ServiceDescriptor
	require.Eventually(t, func() bool {
		var err error
		got, err = c.List(testCtx(t))
		return err == nil && len(got) == n
	}, 30*time.Second, 100*time.Millisecond)
	return got
}

func TestAdvertiseLookupList(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	a, b := serviceKey(t), serviceKey(t)
	advertise(t, f.client(t, a), ctx, descriptor(a, 2))
	advertise(t, f.client(t, b), ctx, descriptor(b, 3))

	reader := f.client(t, nil)
	got, err := reader.Lookup(ctx, a.ID())
	require.NoError(t, err)
	require.Equal(t, descriptor(a, 2), got)

	all := listEventually(t, reader, 2)
	ids := map[common.ServiceID]int{}
	for _, d := range all {
		ids[d.ID()] = len(d.Routers)
	}
	require.Equal(t, map[common.ServiceID]int{a.ID(): 2, b.ID(): 3}, ids)
}

func TestReadvertiseReplaces(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	k := serviceKey(t)
	c := f.client(t, k)
	advertise(t, c, ctx, descriptor(k, 1))
	advertise(t, c, ctx, descriptor(k, 4))
	got, err := f.client(t, nil).Lookup(ctx, k.ID())
	require.NoError(t, err)
	require.Len(t, got.Routers, 4)
}

func TestStaleAndReplayedAdvertise(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	k := serviceKey(t)
	advertise(t, f.client(t, k), ctx, descriptor(k, 2))

	// An old advertisement, e.g. replayed by someone who saw it, loses.
	old := &discovery.AdvertiseRequest{Descriptor: *descriptor(k, 1), Seq: 1, Expiry: in(time.Hour)}
	require.NoError(t, discovery.SignAdvertise(k, f.pk.Public, old))
	reply := handle(t, f, &discovery.DirectoryRequest{Advertise: old})
	require.Equal(t, common.StatusStale, reply.Status)

	// A retransmission of the request in effect is acknowledged again.
	again := &discovery.AdvertiseRequest{Descriptor: *descriptor(k, 3), Seq: 1 << 62, Expiry: in(time.Hour)}
	require.NoError(t, discovery.SignAdvertise(k, f.pk.Public, again))
	require.Equal(t, common.StatusOK, handle(t, f, &discovery.DirectoryRequest{Advertise: again}).Status)
	require.Equal(t, common.StatusOK, handle(t, f, &discovery.DirectoryRequest{Advertise: again}).Status)
}

func TestAdvertiseNeedsTheServiceKey(t *testing.T) {
	f := newFixture(t)
	k, mallory := serviceKey(t), serviceKey(t)
	req := &discovery.AdvertiseRequest{Descriptor: *descriptor(k, 1), Seq: 5}
	require.NoError(t, discovery.SignAdvertise(mallory, f.pk.Public, req))
	require.Equal(t, common.StatusBadMAC, handle(t, f, &discovery.DirectoryRequest{Advertise: req}).Status)
}

func TestWithdraw(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	k := serviceKey(t)
	c := f.client(t, k)
	advertise(t, c, ctx, descriptor(k, 1))
	listEventually(t, f.client(t, nil), 1)

	// Only the service can withdraw it.
	mallory := serviceKey(t)
	forged := &discovery.WithdrawRequest{ServiceID: k.ID(), Seq: 1 << 62}
	require.NoError(t, discovery.SignWithdraw(mallory, f.pk.Public, forged))
	require.Equal(t, common.StatusBadMAC, handle(t, f, &discovery.DirectoryRequest{Withdraw: forged}).Status)

	require.NoError(t, c.Withdraw(ctx, k.ID()))
	_, err := f.client(t, nil).Lookup(ctx, k.ID())
	var se *common.StatusError
	require.ErrorAs(t, err, &se)
	require.Equal(t, common.StatusUnknownService, se.Status)
	listEventually(t, f.client(t, nil), 0)
}

// TestAdvertiseReplayedAfterWithdraw replays an advertisement, as a
// delayed ARQ retransmission would, after the service withdrew.
func TestAdvertiseReplayedAfterWithdraw(t *testing.T) {
	f := newFixture(t)
	k := serviceKey(t)
	adv := &discovery.AdvertiseRequest{Descriptor: *descriptor(k, 1), Seq: 10, Expiry: in(time.Hour)}
	require.NoError(t, discovery.SignAdvertise(k, f.pk.Public, adv))
	require.Equal(t, common.StatusOK, handle(t, f, &discovery.DirectoryRequest{Advertise: adv}).Status)
	wd := &discovery.WithdrawRequest{ServiceID: k.ID(), Seq: 11}
	require.NoError(t, discovery.SignWithdraw(k, f.pk.Public, wd))
	require.Equal(t, common.StatusOK, handle(t, f, &discovery.DirectoryRequest{Withdraw: wd}).Status)
	require.Equal(t, common.StatusOK, handle(t, f, &discovery.DirectoryRequest{Withdraw: wd}).Status)

	require.Equal(t, common.StatusStale, handle(t, f, &discovery.DirectoryRequest{Advertise: adv}).Status)
	_, err := f.client(t, nil).Lookup(testCtx(t), k.ID())
	var se *common.StatusError
	require.ErrorAs(t, err, &se)
	require.Equal(t, common.StatusUnknownService, se.Status)

	again := &discovery.AdvertiseRequest{Descriptor: *descriptor(k, 2), Seq: 12, Expiry: in(time.Hour)}
	require.NoError(t, discovery.SignAdvertise(k, f.pk.Public, again))
	require.Equal(t, common.StatusOK, handle(t, f, &discovery.DirectoryRequest{Advertise: again}).Status)
	got, err := f.client(t, nil).Lookup(testCtx(t), k.ID())
	require.NoError(t, err)
	require.Len(t, got.Routers, 2)
}

func TestSnapshotSpansBoxesAndOldOnesAreTombstoned(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	for range 5 {
		k := serviceKey(t)
		advertise(t, f.client(t, k), ctx, descriptor(k, 3))
	}
	listEventually(t, f.client(t, nil), 5)

	first := handle(t, f, &discovery.DirectoryRequest{List: &discovery.ListRequest{}})
	k := serviceKey(t)
	advertise(t, f.client(t, k), ctx, descriptor(k, 1))
	listEventually(t, f.client(t, nil), 6)

	second := handle(t, f, &discovery.DirectoryRequest{List: &discovery.ListRequest{}})
	require.NotEqual(t, first.ReadCap, second.ReadCap, "a change publishes a fresh stream")
	require.Eventually(t, func() bool {
		rc, idx := snapshotPos(t, first)
		_, tomb, ok := f.net.Box(rc, idx)
		return ok && tomb
	}, 10*time.Second, poll, "the superseded snapshot is tombstoned")
}

func TestStateSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	k := serviceKey(t)
	advertise(t, f.client(t, k), ctx, descriptor(k, 2))
	listEventually(t, f.client(t, nil), 1)

	require.NoError(t, f.dir.Close())
	f.start(t)
	got, err := f.client(t, nil).Lookup(ctx, k.ID())
	require.NoError(t, err)
	require.Len(t, got.Routers, 2)
	listEventually(t, f.client(t, nil), 1)
}

func TestMalformedRequests(t *testing.T) {
	f := newFixture(t)
	for _, req := range []*discovery.DirectoryRequest{
		{},
		{Lookup: &discovery.LookupRequest{}, List: &discovery.ListRequest{}},
	} {
		require.Equal(t, common.StatusInvalidRequest, handle(t, f, req).Status)
	}
	var reply discovery.DirectoryReply
	require.NoError(t, common.Unmarshal(f.dir.Handle([]byte("junk")), &reply))
	require.Equal(t, common.StatusInvalidRequest, reply.Status)
}

func TestAllSpansDirectories(t *testing.T) {
	f := newFixture(t)
	// A second, independent directory.
	pub, priv, err := common.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	pk2 := &common.PluginKey{Scheme: common.DefaultNIKE, Public: pub, Private: priv}
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d2, err := discovery.New(discovery.Config{
		Key: pk2, DBPath: filepath.Join(t.TempDir(), "d2.db"),
		RefreshInterval: time.Hour, Log: logBackend.GetLogger("d2"),
	}, f.net)
	require.NoError(t, err)
	t.Cleanup(func() { d2.Close() })
	f.net.AddService(discovery.DirectoryCapability, [32]byte{0xde}, discovery.DirectoryCapability, common.PluginParams(pk2),
		func(_ context.Context, p []byte) []byte { return d2.Handle(p) })

	ctx := testCtx(t)
	k := serviceKey(t)
	adv, err := discovery.NewAll(f.net, k, poll)
	require.NoError(t, err)
	_, err = adv.Advertise(ctx, descriptor(k, 2), in(time.Hour))
	require.NoError(t, err)

	// Each directory on its own holds it.
	for _, node := range []byte{0xdd, 0xde} {
		nodes, err := f.net.Services(discovery.DirectoryCapability)
		require.NoError(t, err)
		for i := range nodes {
			if nodes[i].NodeIDHash[0] != node {
				continue
			}
			c, err := discovery.NewClientFor(f.net, &nodes[i], nil, poll)
			require.NoError(t, err)
			_, err = c.Lookup(ctx, k.ID())
			require.NoError(t, err)
		}
	}

	reader, err := discovery.NewAll(f.net, nil, poll)
	require.NoError(t, err)
	got, err := reader.Lookup(ctx, k.ID())
	require.NoError(t, err)
	require.Len(t, got.Routers, 2)
	require.Eventually(t, func() bool {
		all, err := reader.List(ctx)
		return err == nil && len(all) == 1
	}, 30*time.Second, 100*time.Millisecond, "the merged list holds the service once")
}
