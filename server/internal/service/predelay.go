// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	mRand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/queue"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

const defaultPreDelayQueueSize = 10 * InboundPacketsChannelSize

type preDelay struct {
	worker.Worker
	sync.Mutex

	q        *queue.PriorityQueue
	mRand    *mRand.Rand
	maxLen   int
	maxDelay atomic.Int64
	wakeCh   chan struct{}
	release  func(*packet.Packet)
	drop     func(*packet.Packet)
}

func newPreDelay(release func(*packet.Packet), maxLen int, drop func(*packet.Packet)) *preDelay {
	if drop == nil {
		drop = func(pkt *packet.Packet) { pkt.Dispose() }
	}
	d := &preDelay{
		q:       queue.New(),
		mRand:   rand.NewMath(),
		maxLen:  maxLen,
		wakeCh:  make(chan struct{}, 1),
		release: release,
		drop:    drop,
	}
	d.Go(d.worker)
	return d
}

func (d *preDelay) setMaxDelay(ms uint64) {
	d.maxDelay.Store(int64(time.Duration(ms) * time.Millisecond))
}

func (d *preDelay) len() int {
	d.Lock()
	defer d.Unlock()
	return d.q.Len()
}

func (d *preDelay) push(pkt *packet.Packet) {
	if max := time.Duration(d.maxDelay.Load()); max > 0 && pkt.Delay > max {
		pkt.Delay = max
	}
	d.Lock()
	d.q.Enqueue(uint64(pkt.RecvAt.Add(pkt.Delay).UnixNano()), pkt)
	var dropped *packet.Packet
	if d.maxLen > 0 && d.q.Len() > d.maxLen {
		dropped = d.q.DequeueRandom(d.mRand).Value.(*packet.Packet)
	}
	d.Unlock()
	if dropped != nil {
		d.drop(dropped)
	}
	select {
	case d.wakeCh <- struct{}{}:
	default:
	}
}

func (d *preDelay) due(now time.Time) ([]*packet.Packet, time.Duration) {
	d.Lock()
	defer d.Unlock()
	var out []*packet.Packet
	for d.q.Len() > 0 {
		e := d.q.Peek()
		at := time.Unix(0, int64(e.Priority))
		if at.After(now) {
			return out, at.Sub(now)
		}
		out = append(out, d.q.Dequeue().(*queue.Entry).Value.(*packet.Packet))
	}
	return out, time.Hour
}

func (d *preDelay) worker() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		now := time.Now()
		ready, wait := d.due(now)
		for _, pkt := range ready {
			pkt.DispatchAt = now
			d.release(pkt)
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
		select {
		case <-d.HaltCh():
			d.Lock()
			var pending []*packet.Packet
			for d.q.Len() > 0 {
				pending = append(pending, d.q.Dequeue().(*queue.Entry).Value.(*packet.Packet))
			}
			d.Unlock()
			for _, pkt := range pending {
				d.drop(pkt)
			}
			return
		case <-d.wakeCh:
		case <-timer.C:
		}
	}
}
