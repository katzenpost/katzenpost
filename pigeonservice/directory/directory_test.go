// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package directory_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	ps "github.com/katzenpost/katzenpost/pigeonservice"
	"github.com/katzenpost/katzenpost/pigeonservice/directory"
	"github.com/katzenpost/katzenpost/pigeonservice/phtest"
)

const poll = 10 * time.Millisecond

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func serviceKey(t *testing.T) *ps.ServiceKey {
	t.Helper()
	pub, priv, err := ps.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	return &ps.ServiceKey{Scheme: ps.DefaultNIKE, Public: pub, Private: priv}
}

type fixture struct {
	net    *phtest.Network
	dir    *directory.Directory
	pk     *ps.PluginKey
	dbPath string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ps.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	f := &fixture{
		net:    phtest.NewNetwork(),
		pk:     &ps.PluginKey{Scheme: ps.DefaultNIKE, Public: pub, Private: priv},
		dbPath: filepath.Join(t.TempDir(), "directory.db"),
	}
	f.net.MaxBox = 200 // small boxes, so a snapshot spans several
	f.start(t)
	f.net.AddService(ps.DirectoryCapability, [32]byte{0xdd}, ps.DirectoryCapability, ps.PluginParams(f.pk),
		func(_ context.Context, payload []byte) []byte { return f.dir.Handle(payload) })
	return f
}

func (f *fixture) start(t *testing.T) {
	t.Helper()
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d, err := directory.New(directory.Config{
		Key:             f.pk,
		DBPath:          f.dbPath,
		RefreshInterval: time.Hour,
		Log:             logBackend.GetLogger("directory"),
	}, f.net)
	require.NoError(t, err)
	f.dir = d
	t.Cleanup(func() { d.Close() })
}

func (f *fixture) client(t *testing.T, key *ps.ServiceKey) *directory.Client {
	t.Helper()
	c, err := directory.NewClient(f.net, key, poll)
	require.NoError(t, err)
	return c
}

func descriptor(key *ps.ServiceKey, routers int) *ps.ServiceDescriptor {
	d := &ps.ServiceDescriptor{NIKEScheme: key.Scheme.Name(), PublicKey: key.Public.Bytes()}
	for i := range routers {
		d.Routers = append(d.Routers, ps.RouterRef{NodeIDHash: [32]byte{byte(i)}, Endpoint: ps.RouterCapability})
	}
	return d
}

func listEventually(t *testing.T, c *directory.Client, n int) []ps.ServiceDescriptor {
	t.Helper()
	var got []ps.ServiceDescriptor
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
	require.NoError(t, f.client(t, a).Advertise(ctx, descriptor(a, 2)))
	require.NoError(t, f.client(t, b).Advertise(ctx, descriptor(b, 3)))

	reader := f.client(t, nil)
	got, err := reader.Lookup(ctx, a.ID())
	require.NoError(t, err)
	require.Equal(t, descriptor(a, 2), got)

	all := listEventually(t, reader, 2)
	ids := map[ps.ServiceID]int{}
	for _, d := range all {
		ids[d.ID()] = len(d.Routers)
	}
	require.Equal(t, map[ps.ServiceID]int{a.ID(): 2, b.ID(): 3}, ids)
}

func TestReadvertiseReplaces(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	k := serviceKey(t)
	c := f.client(t, k)
	require.NoError(t, c.Advertise(ctx, descriptor(k, 1)))
	require.NoError(t, c.Advertise(ctx, descriptor(k, 4)))
	got, err := f.client(t, nil).Lookup(ctx, k.ID())
	require.NoError(t, err)
	require.Len(t, got.Routers, 4)
}

func TestStaleAndReplayedAdvertise(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	k := serviceKey(t)
	require.NoError(t, f.client(t, k).Advertise(ctx, descriptor(k, 2)))

	// An old advertisement, e.g. replayed by someone who saw it, loses.
	old := &ps.AdvertiseRequest{Descriptor: *descriptor(k, 1), Seq: 1}
	require.NoError(t, k.SignAdvertise(f.pk.Public, old))
	reply := handle(t, f, &ps.DirectoryRequest{Advertise: old})
	require.Equal(t, ps.StatusStale, reply.Status)

	// A retransmission of the request in effect is acknowledged again.
	again := &ps.AdvertiseRequest{Descriptor: *descriptor(k, 3), Seq: 1 << 62}
	require.NoError(t, k.SignAdvertise(f.pk.Public, again))
	require.Equal(t, ps.StatusOK, handle(t, f, &ps.DirectoryRequest{Advertise: again}).Status)
	require.Equal(t, ps.StatusOK, handle(t, f, &ps.DirectoryRequest{Advertise: again}).Status)
}

func TestAdvertiseNeedsTheServiceKey(t *testing.T) {
	f := newFixture(t)
	k, mallory := serviceKey(t), serviceKey(t)
	req := &ps.AdvertiseRequest{Descriptor: *descriptor(k, 1), Seq: 5}
	require.NoError(t, mallory.SignAdvertise(f.pk.Public, req))
	require.Equal(t, ps.StatusBadMAC, handle(t, f, &ps.DirectoryRequest{Advertise: req}).Status)
}

func TestWithdraw(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	k := serviceKey(t)
	c := f.client(t, k)
	require.NoError(t, c.Advertise(ctx, descriptor(k, 1)))
	listEventually(t, f.client(t, nil), 1)

	// Only the service can withdraw it.
	mallory := serviceKey(t)
	forged := &ps.WithdrawRequest{ServiceID: k.ID(), Seq: 1 << 62}
	require.NoError(t, mallory.SignWithdraw(f.pk.Public, forged))
	require.Equal(t, ps.StatusBadMAC, handle(t, f, &ps.DirectoryRequest{Withdraw: forged}).Status)

	require.NoError(t, c.Withdraw(ctx, k.ID()))
	_, err := f.client(t, nil).Lookup(ctx, k.ID())
	var se *ps.StatusError
	require.ErrorAs(t, err, &se)
	require.Equal(t, ps.StatusUnknownService, se.Status)
	listEventually(t, f.client(t, nil), 0)
}

// TestAdvertiseReplayedAfterWithdraw replays an advertisement, as a
// delayed ARQ retransmission would, after the service withdrew.
func TestAdvertiseReplayedAfterWithdraw(t *testing.T) {
	f := newFixture(t)
	k := serviceKey(t)
	adv := &ps.AdvertiseRequest{Descriptor: *descriptor(k, 1), Seq: 10}
	require.NoError(t, k.SignAdvertise(f.pk.Public, adv))
	require.Equal(t, ps.StatusOK, handle(t, f, &ps.DirectoryRequest{Advertise: adv}).Status)
	wd := &ps.WithdrawRequest{ServiceID: k.ID(), Seq: 11}
	require.NoError(t, k.SignWithdraw(f.pk.Public, wd))
	require.Equal(t, ps.StatusOK, handle(t, f, &ps.DirectoryRequest{Withdraw: wd}).Status)
	require.Equal(t, ps.StatusOK, handle(t, f, &ps.DirectoryRequest{Withdraw: wd}).Status)

	require.Equal(t, ps.StatusStale, handle(t, f, &ps.DirectoryRequest{Advertise: adv}).Status)
	_, err := f.client(t, nil).Lookup(testCtx(t), k.ID())
	var se *ps.StatusError
	require.ErrorAs(t, err, &se)
	require.Equal(t, ps.StatusUnknownService, se.Status)

	again := &ps.AdvertiseRequest{Descriptor: *descriptor(k, 2), Seq: 12}
	require.NoError(t, k.SignAdvertise(f.pk.Public, again))
	require.Equal(t, ps.StatusOK, handle(t, f, &ps.DirectoryRequest{Advertise: again}).Status)
	got, err := f.client(t, nil).Lookup(testCtx(t), k.ID())
	require.NoError(t, err)
	require.Len(t, got.Routers, 2)
}

func TestSnapshotSpansBoxesAndOldOnesAreTombstoned(t *testing.T) {
	f := newFixture(t)
	ctx := testCtx(t)
	for range 5 {
		k := serviceKey(t)
		require.NoError(t, f.client(t, k).Advertise(ctx, descriptor(k, 3)))
	}
	listEventually(t, f.client(t, nil), 5)

	first := handle(t, f, &ps.DirectoryRequest{List: &ps.ListRequest{}})
	k := serviceKey(t)
	require.NoError(t, f.client(t, k).Advertise(ctx, descriptor(k, 1)))
	listEventually(t, f.client(t, nil), 6)

	second := handle(t, f, &ps.DirectoryRequest{List: &ps.ListRequest{}})
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
	require.NoError(t, f.client(t, k).Advertise(ctx, descriptor(k, 2)))
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
	for _, req := range []*ps.DirectoryRequest{
		{},
		{Lookup: &ps.LookupRequest{}, List: &ps.ListRequest{}},
	} {
		require.Equal(t, ps.StatusInvalidRequest, handle(t, f, req).Status)
	}
	var reply ps.DirectoryReply
	require.NoError(t, ps.Unmarshal(f.dir.Handle([]byte("junk")), &reply))
	require.Equal(t, ps.StatusInvalidRequest, reply.Status)
}

func TestAllSpansDirectories(t *testing.T) {
	f := newFixture(t)
	// A second, independent directory.
	pub, priv, err := ps.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	pk2 := &ps.PluginKey{Scheme: ps.DefaultNIKE, Public: pub, Private: priv}
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d2, err := directory.New(directory.Config{
		Key: pk2, DBPath: filepath.Join(t.TempDir(), "d2.db"),
		RefreshInterval: time.Hour, Log: logBackend.GetLogger("d2"),
	}, f.net)
	require.NoError(t, err)
	t.Cleanup(func() { d2.Close() })
	f.net.AddService(ps.DirectoryCapability, [32]byte{0xde}, ps.DirectoryCapability, ps.PluginParams(pk2),
		func(_ context.Context, p []byte) []byte { return d2.Handle(p) })

	ctx := testCtx(t)
	k := serviceKey(t)
	adv, err := directory.NewAll(f.net, k, poll)
	require.NoError(t, err)
	require.NoError(t, adv.Advertise(ctx, descriptor(k, 2)))

	// Each directory on its own holds it.
	for _, node := range []byte{0xdd, 0xde} {
		nodes, err := f.net.Services(ps.DirectoryCapability)
		require.NoError(t, err)
		for i := range nodes {
			if nodes[i].NodeIDHash[0] != node {
				continue
			}
			c, err := directory.NewClientFor(f.net, &nodes[i], nil, poll)
			require.NoError(t, err)
			_, err = c.Lookup(ctx, k.ID())
			require.NoError(t, err)
		}
	}

	reader, err := directory.NewAll(f.net, nil, poll)
	require.NoError(t, err)
	got, err := reader.Lookup(ctx, k.ID())
	require.NoError(t, err)
	require.Len(t, got.Routers, 2)
	require.Eventually(t, func() bool {
		all, err := reader.List(ctx)
		return err == nil && len(all) == 1
	}, 30*time.Second, 100*time.Millisecond, "the merged list holds the service once")
}
