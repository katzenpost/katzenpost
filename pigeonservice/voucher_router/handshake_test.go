// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package voucher_router_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/common/phtest"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
)

// handshake runs a joiner and an inductor against one network.
func handshake(t *testing.T, net *phtest.Network) (joiner, inductor *voucher_router.Conn) {
	t.Helper()
	ctx := testCtx(t)
	pending, err := voucher_router.Mint(ctx, net, "client")
	require.NoError(t, err)

	var wg sync.WaitGroup
	var inductErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		inductor, inductErr = voucher_router.Induct(ctx, net, pending.Voucher, "service", poll)
	}()
	joiner, err = pending.Await(ctx, net, poll)
	require.NoError(t, err)
	wg.Wait()
	require.NoError(t, inductErr)
	return joiner, inductor
}

func TestHandshakeOpensATwoWayConnection(t *testing.T) {
	net := phtest.NewNetwork()
	joiner, inductor := handshake(t, net)
	ctx := testCtx(t)

	require.NoError(t, joiner.Send(ctx, []byte("hello service")))
	got, err := inductor.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("hello service"), got)

	require.NoError(t, inductor.Send(ctx, []byte("hello client")))
	got, err = joiner.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("hello client"), got)

	for i := range 5 {
		require.NoError(t, joiner.Send(ctx, []byte{byte(i) + 1}))
	}
	for i := range 5 {
		got, err := inductor.Recv(ctx)
		require.NoError(t, err)
		require.Equal(t, []byte{byte(i) + 1}, got, "messages arrive in order")
	}
}

func TestInductBeforeMintIsPublishedWaits(t *testing.T) {
	net := phtest.NewNetwork()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := voucher_router.Induct(ctx, net, make([]byte, 32), "service", poll)
	require.ErrorIs(t, err, context.DeadlineExceeded, "box 0 never appears, so induction waits")
}

func TestConnSkipsTombstones(t *testing.T) {
	net := phtest.NewNetwork()
	joiner, inductor := handshake(t, net)
	ctx := testCtx(t)

	// The joiner's owner tombstones its next box and writes after it.
	st, err := joiner.State()
	require.NoError(t, err)
	wc, err := bacap.NewWriteCapFromBytes(st.WriteCap)
	require.NoError(t, err)
	idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(st.WriteIdx)
	require.NoError(t, err)
	require.NoError(t, net.Tombstone(ctx, wc, idx))
	next, err := idx.NextIndex()
	require.NoError(t, err)
	st.WriteIdx, err = next.MarshalBinary()
	require.NoError(t, err)
	after, err := voucher_router.RestoreConn(net, st, poll)
	require.NoError(t, err)
	require.NoError(t, after.Send(ctx, []byte("past the tombstone")))

	got, err := inductor.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("past the tombstone"), got)
}

func TestConnStateRoundTrip(t *testing.T) {
	net := phtest.NewNetwork()
	joiner, inductor := handshake(t, net)
	ctx := testCtx(t)

	require.NoError(t, joiner.Send(ctx, []byte("before restart")))
	st, err := joiner.State()
	require.NoError(t, err)
	blob, err := common.Marshal(st)
	require.NoError(t, err)

	var decoded voucher_router.ConnState
	require.NoError(t, common.Unmarshal(blob, &decoded))
	again, err := voucher_router.RestoreConn(net, &decoded, poll)
	require.NoError(t, err)
	require.NoError(t, again.Send(ctx, []byte("after restart")))

	for _, want := range []string{"before restart", "after restart"} {
		got, err := inductor.Recv(ctx)
		require.NoError(t, err)
		require.Equal(t, want, string(got))
	}
}

func TestConnRejectsOversizeMessages(t *testing.T) {
	net := phtest.NewNetwork()
	joiner, _ := handshake(t, net)
	err := joiner.Send(testCtx(t), make([]byte, net.MaxPlaintext()+1))
	require.ErrorIs(t, err, voucher_router.ErrMessageTooLarge)
}

func TestRefreshRestoresGarbageCollectedBoxes(t *testing.T) {
	net := phtest.NewNetwork()
	joiner, inductor := handshake(t, net)
	ctx := testCtx(t)

	require.NoError(t, joiner.Send(ctx, []byte("keep me")))

	// The inductor's view of the joiner's stream starts where the joiner
	// first wrote.
	ist, err := inductor.State()
	require.NoError(t, err)
	rc, idx := readPos(t, ist)
	_, _, ok := net.Box(rc, idx)
	require.True(t, ok)
	net.Forget(rc, idx)
	_, _, ok = net.Box(rc, idx)
	require.False(t, ok, "the replica garbage-collected the box")

	require.NoError(t, joiner.Refresh(ctx, time.Hour))
	got, _, ok := net.Box(rc, idx)
	require.True(t, ok)
	require.Equal(t, []byte("keep me"), got)

	msg, err := inductor.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("keep me"), msg)

	// Past retention the box is forgotten and not rewritten.
	net.Forget(rc, idx)
	require.NoError(t, joiner.Refresh(ctx, -time.Second))
	_, _, ok = net.Box(rc, idx)
	require.False(t, ok)
}

func TestPendingStateRoundTrip(t *testing.T) {
	net := phtest.NewNetwork()
	ctx := testCtx(t)
	pending, err := voucher_router.Mint(ctx, net, "client")
	require.NoError(t, err)
	st, err := pending.State()
	require.NoError(t, err)
	b, err := common.Marshal(st)
	require.NoError(t, err)
	var st2 voucher_router.PendingState
	require.NoError(t, common.Unmarshal(b, &st2))
	restored, err := voucher_router.RestorePending(&st2)
	require.NoError(t, err)
	require.Equal(t, pending.Voucher, restored.Voucher)

	inductor, err := voucher_router.Induct(ctx, net, restored.Voucher, "service", poll)
	require.NoError(t, err)
	joiner, err := restored.Await(ctx, net, poll)
	require.NoError(t, err)
	require.NoError(t, joiner.Send(ctx, []byte("restored")))
	got, err := inductor.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("restored"), got)
}
