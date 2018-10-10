// scheduler.go - Katzenpost server scheduler.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package scheduler implements the Katzenpost server scheduler.
package scheduler

import (
	"math"
	"time"

	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/monotime"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/server/internal/constants"
	"github.com/katzenpost/server/internal/debug"
	"github.com/katzenpost/server/internal/glue"
	"github.com/katzenpost/server/internal/packet"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

type queueImpl interface {
	Halt()
	Peek() (time.Duration, *packet.Packet)
	Pop()
	BulkEnqueue([]*packet.Packet)
}

type scheduler struct {
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	q          queueImpl
	inCh       *channels.InfiniteChannel
	outCh      *channels.BatchingChannel
	maxDelayCh chan uint64
}

func (sch *scheduler) Halt() {
	sch.Worker.Halt()
	sch.inCh.Close()
	sch.q.Halt()
}

func (sch *scheduler) OnNewMixMaxDelay(newMixMaxDelay uint64) {
	sch.maxDelayCh <- newMixMaxDelay
}

func (sch *scheduler) OnPacket(pkt *packet.Packet) {
	sch.inCh.In() <- pkt
}

func (sch *scheduler) worker() {
	var absoluteMaxDelay = epochtime.Period * constants.NumMixKeys

	timerSlack := time.Duration(sch.glue.Config().Debug.SchedulerSlack) * time.Millisecond
	timer := time.NewTimer(math.MaxInt64)
	defer timer.Stop()

	maxDelay := absoluteMaxDelay
	for {
		var timerFired bool
		// The vast majority of the time the scheduler will be idle waiting on
		// new packets or for a packet in the priority queue to be eligible
		// for dispatch.  This is where the actual "mix" part of the mix
		// network happens.
		//
		// There's only a single go routine responsible for packet scheduling
		// under the assumption that this isn't CPU intensive in the slightest,
		// and that the main performance gains come from parallelizing the
		// crypto, and being clever about congestion management.
		select {
		case <-sch.HaltCh():
			// Th-th-th-that's all folks.
			sch.log.Debugf("Terminating gracefully.")
			return
		case iBatch := <-sch.outCh.Out():
			batch := iBatch.([]interface{})
			sch.log.Debugf("Batch processing %v packets.", len(batch))
			toEnqueue := make([]*packet.Packet, 0, len(batch))
			for _, e := range batch {
				// New packet from the crypto workers.
				//
				// Note: This assumes that pkt.delay has already been adjusted
				// to account for the packet processing time up to the point
				// where the packet was enqueued.
				pkt := e.(*packet.Packet)

				// Ensure that the packet's delay is not pathologically malformed.
				if pkt.Delay > maxDelay {
					sch.log.Debugf("Dropping packet: %v (Delay exceeds max: %v)", pkt.ID, pkt.Delay)
					pkt.Dispose()
					continue
				}

				// Ensure the peer is valid by querying the outgoing connection
				// table.
				if sch.glue.Connector().IsValidForwardDest(&pkt.NextNodeHop.ID) {
					sch.log.Debugf("Enqueueing packet: %v delta-t: %v", pkt.ID, pkt.Delay)
					toEnqueue = append(toEnqueue, pkt)
				} else {
					sID := debug.NodeIDToPrintString(&pkt.NextNodeHop.ID)
					sch.log.Debugf("Dropping packet: %v (Next hop is invalid: %v)", pkt.ID, sID)
					pkt.Dispose()
				}
			}
			sch.q.BulkEnqueue(toEnqueue)
		case newMaxDelay := <-sch.maxDelayCh:
			pkiMaxDelay := time.Duration(newMaxDelay) * time.Millisecond
			if pkiMaxDelay > absoluteMaxDelay || pkiMaxDelay == 0 {
				// There is a maximum sensible delay, regardless of what the
				// document happens to specify.
				maxDelay = absoluteMaxDelay
			} else {
				maxDelay = pkiMaxDelay
			}
			sch.log.Debugf("New PKI MixMaxDelay %v, using %v.", pkiMaxDelay, maxDelay)
		case <-timer.C:
			// Packet delay probably passed, packet dispatch handled as
			// part of rescheduling the timer.
			timerFired = true
		}

		// Dispatch packets if possible and reschedule the next wakeup.
		if !timerFired && !timer.Stop() {
			<-timer.C
		}

		nrBurst, maxBurst := 0, sch.glue.Config().Debug.SchedulerMaxBurst
		for {
			// Peek at the next packet in the queue.
			dispatchAt, pkt := sch.q.Peek()
			if pkt == nil {
				// The queue is empty, just reschedule for the max duration,
				// when there are packets to schedule, we'll get woken up.
				timer.Reset(math.MaxInt64)
				break
			}

			// Figure out if the packet needs to be handled now.
			now := monotime.Now()
			if dispatchAt > now {
				// Packet dispatch will happen at a later time, so schedule
				// the next timer tick, and go back to waiting for something
				// interesting to happen.
				timer.Reset(dispatchAt - now)
				break
			}
			if nrBurst = nrBurst + 1; nrBurst > maxBurst {
				// Packet dispatch is supposed to happen "now", but we've
				// already sent up to the max burst size.
				//
				// Note: This is primarily to prevent the inbound scheduler
				// queue from encountering pathological backlog.
				timer.Reset(1 * time.Microsecond)
				break
			}

			// The packet will be dispatched somehow, so remove it from the
			// queue, and do the type assertion.
			sch.q.Pop()

			// Packet dispatch time is now or in the past, so it needs to be
			// forwarded to the appropriate hop.
			if now-dispatchAt > timerSlack {
				// ... unless the deadline has been blown by more than the
				// configured slack time.
				sch.log.Debugf("Dropping packet: %v (Deadline blown by %v)", pkt.ID, now-dispatchAt)
				pkt.Dispose()
			} else {
				// Dispatch the packet to the next hop.  Note that the callee
				// may still drop the packet, for example if there isn't a
				// link establised to the peer, or if the link is overloaded.
				//
				// Note: Callee takes ownership.
				pkt.DispatchAt = now
				sch.glue.Connector().DispatchPacket(pkt)
			}
		}
	}

	// NOTREACHED
}

// New constructs a new scheduler instance.
func New(glue glue.Glue) (glue.Scheduler, error) {
	const maxBatchSize = 64 // XXX: Tune.

	sch := &scheduler{
		glue:       glue,
		log:        glue.LogBackend().GetLogger("scheduler"),
		inCh:       channels.NewInfiniteChannel(),
		outCh:      channels.NewBatchingChannel(maxBatchSize),
		maxDelayCh: make(chan uint64),
	}

	if glue.Config().Debug.SchedulerExternalMemoryQueue {
		sch.log.Noticef("Initializing external memory queue.")
		var err error
		sch.q, err = newBoltQueue(glue)
		if err != nil {
			return nil, err
		}
	} else {
		sch.log.Noticef("Initializing memory queue.")
		sch.q = newMemoryQueue(glue, sch.log)
	}
	channels.Pipe(sch.inCh, sch.outCh)

	sch.Go(sch.worker)
	return sch, nil
}
