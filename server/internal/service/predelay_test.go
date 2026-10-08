// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/server/internal/packet"
)

type releases struct {
	sync.Mutex
	at   map[uint64]time.Time
	pkts map[uint64]*packet.Packet
	ch   chan uint64
}

func newReleases() *releases {
	return &releases{
		at:   make(map[uint64]time.Time),
		pkts: make(map[uint64]*packet.Packet),
		ch:   make(chan uint64, 64),
	}
}

func (r *releases) release(pkt *packet.Packet) {
	r.Lock()
	r.at[pkt.ID] = time.Now()
	r.pkts[pkt.ID] = pkt
	r.Unlock()
	r.ch <- pkt.ID
}

func (r *releases) wait(t *testing.T, n int, timeout time.Duration) {
	deadline := time.After(timeout)
	for i := 0; i < n; i++ {
		select {
		case <-r.ch:
		case <-deadline:
			t.Fatalf("only %d of %d packets released within %v", i, n, timeout)
		}
	}
}

func testPacket(id uint64, delay time.Duration) *packet.Packet {
	now := time.Now()
	return &packet.Packet{ID: id, Delay: delay, RecvAt: now, DispatchAt: now}
}

func TestPreDelayHoldsUntilDue(t *testing.T) {
	r := newReleases()
	d := newPreDelay(r.release, 0, nil)
	defer d.Halt()

	pkt := testPacket(1, 300*time.Millisecond)
	d.push(pkt)

	select {
	case <-r.ch:
		t.Fatal("packet released before its delay")
	case <-time.After(200 * time.Millisecond):
	}
	r.wait(t, 1, 2*time.Second)

	r.Lock()
	defer r.Unlock()
	require.GreaterOrEqual(t, r.at[1].Sub(pkt.RecvAt), 300*time.Millisecond)
}

func TestPreDelayZeroDelayReleasesAtOnce(t *testing.T) {
	r := newReleases()
	d := newPreDelay(r.release, 0, nil)
	defer d.Halt()

	d.push(testPacket(1, 0))
	r.wait(t, 1, time.Second)
}

func TestPreDelayReleasesInDueOrder(t *testing.T) {
	r := newReleases()
	d := newPreDelay(r.release, 0, nil)
	defer d.Halt()

	d.push(testPacket(1, 400*time.Millisecond))
	d.push(testPacket(2, 100*time.Millisecond))
	d.push(testPacket(3, 250*time.Millisecond))

	order := make([]uint64, 0, 3)
	for i := 0; i < 3; i++ {
		select {
		case id := <-r.ch:
			order = append(order, id)
		case <-time.After(2 * time.Second):
			t.Fatal("timed out")
		}
	}
	require.Equal(t, []uint64{2, 3, 1}, order)
}

func TestPreDelayResetsDispatchAt(t *testing.T) {
	r := newReleases()
	d := newPreDelay(r.release, 0, nil)
	defer d.Halt()

	pkt := testPacket(1, 200*time.Millisecond)
	enqueued := pkt.DispatchAt
	d.push(pkt)
	r.wait(t, 1, 2*time.Second)

	r.Lock()
	defer r.Unlock()
	require.GreaterOrEqual(t, r.pkts[1].DispatchAt.Sub(enqueued), 200*time.Millisecond)
	require.WithinDuration(t, r.at[1], r.pkts[1].DispatchAt, 50*time.Millisecond)
}

func TestPreDelayClampsToMaxDelay(t *testing.T) {
	r := newReleases()
	d := newPreDelay(r.release, 0, nil)
	defer d.Halt()
	d.setMaxDelay(100)

	pkt := testPacket(1, 10*time.Second)
	d.push(pkt)
	r.wait(t, 1, 2*time.Second)

	r.Lock()
	defer r.Unlock()
	require.Equal(t, 100*time.Millisecond, r.pkts[1].Delay)
	require.Less(t, r.at[1].Sub(pkt.RecvAt), time.Second)
}

func TestPreDelayNoCapUntilKnown(t *testing.T) {
	r := newReleases()
	d := newPreDelay(r.release, 0, nil)
	defer d.Halt()

	pkt := testPacket(1, 300*time.Millisecond)
	d.push(pkt)
	r.wait(t, 1, 2*time.Second)

	r.Lock()
	defer r.Unlock()
	require.Equal(t, 300*time.Millisecond, r.pkts[1].Delay)
}

func TestPreDelayOverflowDropsRandomEntry(t *testing.T) {
	const capacity = 4
	survivors := make(map[string]bool)
	for trial := 0; trial < 40; trial++ {
		var dropped []uint64
		var mu sync.Mutex
		d := newPreDelay(func(*packet.Packet) {}, capacity, func(pkt *packet.Packet) {
			mu.Lock()
			dropped = append(dropped, pkt.ID)
			mu.Unlock()
		})
		for id := uint64(1); id <= capacity+2; id++ {
			d.push(testPacket(id, time.Hour))
		}
		require.Equal(t, capacity, d.len())
		mu.Lock()
		require.Len(t, dropped, 2)
		key := ""
		for _, id := range dropped {
			key += string(rune('0' + id))
		}
		mu.Unlock()
		survivors[key] = true
		d.Halt()
	}
	require.Greater(t, len(survivors), 1, "overflow always dropped the same entries")
}

func TestPreDelayHaltDropsPending(t *testing.T) {
	var dropped []uint64
	var mu sync.Mutex
	d := newPreDelay(func(*packet.Packet) { t.Error("released after halt") }, 0, func(pkt *packet.Packet) {
		mu.Lock()
		dropped = append(dropped, pkt.ID)
		mu.Unlock()
	})
	d.push(testPacket(1, time.Hour))
	d.push(testPacket(2, time.Hour))
	d.Halt()

	mu.Lock()
	defer mu.Unlock()
	require.ElementsMatch(t, []uint64{1, 2}, dropped)
}

func TestServiceNodeOnNewMixMaxDelay(t *testing.T) {
	r := newReleases()
	d := newPreDelay(r.release, 0, nil)
	defer d.Halt()
	p := &serviceNode{preDelay: d}

	p.OnNewMixMaxDelay(50)
	pkt := testPacket(1, time.Hour)
	d.push(pkt)
	r.wait(t, 1, 2*time.Second)

	r.Lock()
	defer r.Unlock()
	require.Equal(t, 50*time.Millisecond, r.pkts[1].Delay)
}

func TestServiceNodeOnNewMixMaxDelayDisabled(t *testing.T) {
	p := &serviceNode{}
	p.OnNewMixMaxDelay(50)
}
