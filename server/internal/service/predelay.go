// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	mRand "math/rand"
	"sync/atomic"
	"time"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/queue"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

const defaultPreDelayQueueSize = 10 * InboundPacketsChannelSize

type preDelay struct {
	tq       *queue.TimerQueue
	mRand    *mRand.Rand
	maxLen   int
	maxDelay atomic.Int64
	drop     func(*packet.Packet)
}

func newPreDelay(release func(*packet.Packet), maxLen int, drop func(*packet.Packet)) *preDelay {
	if drop == nil {
		drop = func(pkt *packet.Packet) { pkt.Dispose() }
	}
	d := &preDelay{
		mRand:  rand.NewMath(),
		maxLen: maxLen,
		drop:   drop,
	}
	d.tq = queue.NewTimerQueue(func(v interface{}) {
		pkt := v.(*packet.Packet)
		pkt.DispatchAt = time.Now()
		release(pkt)
	})
	d.tq.Start()
	return d
}

func (d *preDelay) setMaxDelay(ms uint64) {
	d.maxDelay.Store(int64(time.Duration(ms) * time.Millisecond))
}

func (d *preDelay) len() int {
	return d.tq.Len()
}

func (d *preDelay) push(pkt *packet.Packet) {
	if max := time.Duration(d.maxDelay.Load()); max > 0 && pkt.Delay > max {
		pkt.Delay = max
	}
	if v := d.tq.PushBounded(uint64(pkt.RecvAt.Add(pkt.Delay).UnixNano()), pkt, d.maxLen, d.mRand); v != nil {
		d.drop(v.(*packet.Packet))
	}
}

func (d *preDelay) Halt() {
	d.tq.Halt()
	for e := d.tq.Pop(); e != nil; e = d.tq.Pop() {
		d.drop(e.(*queue.Entry).Value.(*packet.Packet))
	}
}
