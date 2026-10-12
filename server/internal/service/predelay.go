// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	mRand "math/rand"
	"sync/atomic"
	"time"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/queue"
	"github.com/katzenpost/katzenpost/server/internal/constants"
	"github.com/katzenpost/katzenpost/server/internal/maxdelay"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

const defaultPreDelayQueueSize = 10 * InboundPacketsChannelSize

type preDelay struct {
	tq                    *queue.TimerQueue
	mRand                 *mRand.Rand
	maxLen                int
	fallbackMs            int
	maxDelay              atomic.Int64
	maxDelayFromConsensus atomic.Bool
	drop                  func(*packet.Packet)
}

func preDelayCeiling() time.Duration {
	return epochtime.Period() * constants.NumMixKeys
}

func newPreDelay(release func(*packet.Packet), maxLen int, drop func(*packet.Packet), fallbackMs int) *preDelay {
	if drop == nil {
		drop = func(pkt *packet.Packet) { pkt.Dispose() }
	}
	d := &preDelay{
		mRand:      rand.NewMath(),
		maxLen:     maxLen,
		fallbackMs: fallbackMs,
		drop:       drop,
	}
	d.setMaxDelay(0)
	d.tq = queue.NewTimerQueue(func(v interface{}) {
		pkt := v.(*packet.Packet)
		pkt.DispatchAt = time.Now()
		release(pkt)
	})
	d.tq.Start()
	return d
}

func (d *preDelay) setMaxDelay(consensusMs uint64) (limit time.Duration, fromConsensus, changed bool) {
	limit, fromConsensus = maxdelay.Effective(consensusMs, d.fallbackMs, preDelayCeiling())
	limitChanged := time.Duration(d.maxDelay.Swap(int64(limit))) != limit
	sourceChanged := d.maxDelayFromConsensus.Swap(fromConsensus) != fromConsensus
	return limit, fromConsensus, limitChanged || sourceChanged
}

func (d *preDelay) len() int {
	return d.tq.Len()
}

func (d *preDelay) push(pkt *packet.Packet) bool {
	if pkt.Delay > time.Duration(d.maxDelay.Load()) {
		return false
	}
	if v := d.tq.PushBounded(uint64(pkt.RecvAt.Add(pkt.Delay).UnixNano()), pkt, d.maxLen, d.mRand); v != nil {
		d.drop(v.(*packet.Packet))
	}
	return true
}

func (d *preDelay) Halt() {
	d.tq.Halt()
	for e := d.tq.Pop(); e != nil; e = d.tq.Pop() {
		d.drop(e.(*queue.Entry).Value.(*packet.Packet))
	}
}
