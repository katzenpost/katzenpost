// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"
	mrand "math/rand"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/queue"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/replica/instrument"
)

// senderRequest represents a command to send to a peer.
// recvAt is set by processCommands at the moment the inbound command
// finished decoding; the emitter uses it to record the per-reply
// latency histogram (t_emit - t_recv) for the privacy gate.
type senderRequest struct {
	ReplicaDecoy        *commands.ReplicaDecoy
	ReplicaWriteReply   *commands.ReplicaWriteReply
	ReplicaMessageReply *commands.ReplicaMessageReply
	recvAt              time.Time
}

func (s *senderRequest) command() commands.Command {
	if s.ReplicaDecoy != nil {
		return s.ReplicaDecoy
	}
	if s.ReplicaWriteReply != nil {
		return s.ReplicaWriteReply
	}
	if s.ReplicaMessageReply != nil {
		return s.ReplicaMessageReply
	}
	return nil
}

// replyJitterMax bounds the per-reply uniform random delay applied by
// delayedReplyEmitter on incoming connections. This generalises §5.4 of
// the Echomix paper ("Each reply is independently delayed, with delays
// sampled from a uniform distribution") to all replies, so that
// per-reply latency hides processing-time variance and the wire stays
// at a constant Poisson rate driven by the peer's command rate.
//
// Expected steady-state TimerQueue depth per connection by Little's
// Law is LambdaR * replyJitterMax / 2, which at the docker default
// LambdaR = 0.005 (5 events/s per pair) is about 0.125 items.
const replyJitterMax = 50 * time.Millisecond

// delayedReplyEmitter takes the place of the older paced "sender" on
// the responder side of every incoming connection. processCommands
// calls Enqueue for each reply (real or decoy-in-response-to-peer-decoy),
// the emitter draws an i.i.d. delay from Uniform[0, replyJitterMax]
// and pushes the reply into a TimerQueue keyed by ready-at time.
// The TimerQueue's worker emits each reply to the egress channel when
// its delay elapses. There is no LambdaR-paced consumer here; the
// reply rate equals the peer's command rate by 1:1 correspondence and
// no fresh decoys are generated on this side.
type delayedReplyEmitter struct {
	log      *logging.Logger
	out      chan *senderRequest
	tq       *queue.TimerQueue
	rng      *mrand.Rand
	rngLock  sync.Mutex
	peerName string
}

func newDelayedReplyEmitter(out chan *senderRequest, logBackend *log.Backend, peerName string) *delayedReplyEmitter {
	e := &delayedReplyEmitter{
		log:      logBackend.GetLogger("replica/delayedReplyEmitter"),
		out:      out,
		rng:      mrand.New(mrand.NewSource(time.Now().UnixNano())),
		peerName: peerName,
	}
	e.tq = queue.NewTimerQueue(func(v interface{}) {
		req := v.(*senderRequest)
		// Halt path: tq.HaltCh() closes when Halt() is called, which
		// lets a stuck send exit promptly when the connection retires.
		select {
		case e.out <- req:
		case <-e.tq.HaltCh():
			return
		}
		latency := time.Since(req.recvAt)
		if req.ReplicaDecoy != nil {
			instrument.IncomingDecoyReplyEmitted(latency)
		} else {
			instrument.IncomingRealReplyEmitted(latency)
		}
	})
	e.tq.Start()
	return e
}

// Enqueue schedules a reply for emission after a Uniform[0,
// replyJitterMax] delay. Safe for concurrent use.
func (e *delayedReplyEmitter) Enqueue(reply *senderRequest) {
	e.rngLock.Lock()
	delayNs := e.rng.Int63n(int64(replyJitterMax))
	e.rngLock.Unlock()
	readyAt := uint64(time.Now().UnixNano() + delayNs)
	e.tq.Push(readyAt, reply)
	instrument.IncomingQueueLength(e.peerName, e.tq.Len())
}

// Halt stops the underlying TimerQueue and waits for its worker to
// exit. Safe to call multiple times.
func (e *delayedReplyEmitter) Halt() { e.tq.Halt() }

// Len reports the depth of the underlying TimerQueue.
func (e *delayedReplyEmitter) Len() int { return e.tq.Len() }

// outgoingSender is a sender for outgoing replica-to-replica connections.
// It works on commands.Command. On each ExpDist tick it sends a real
// command from the queue if available, otherwise a decoy. This is the
// originator side; the producer (replication writes) operates at
// rho << 1 so the M/M/1 boundary case that motivated the responder
// redesign does not apply here.
type outgoingSender struct {
	worker.Worker

	log              *logging.Logger
	in               chan commands.Command
	out              chan commands.Command
	sendQueryOrDecoy *common.ExpDist
	disableDecoys    bool
	peerName         string

	commands *commands.Commands
}

func newOutgoingSender(in chan commands.Command, out chan commands.Command, disableDecoys bool, logBackend *log.Backend, cmds *commands.Commands, peerName string) *outgoingSender {
	s := &outgoingSender{
		log:              logBackend.GetLogger("replica/outgoing_sender"),
		in:               in,
		out:              out,
		sendQueryOrDecoy: common.NewExpDist(),
		disableDecoys:    disableDecoys,
		commands:         cmds,
		peerName:         peerName,
	}
	s.Go(s.worker)
	return s
}

func (s *outgoingSender) halt() {
	s.log.Debug("outgoing sender stopping ExpDist worker")
	s.sendQueryOrDecoy.Halt()
}

func (s *outgoingSender) worker() {
	defer s.halt()
	for {
		select {
		case <-s.HaltCh():
			return
		case <-s.sendQueryOrDecoy.OutCh():
			var toSend commands.Command
			select {
			case toSend = <-s.in:
				instrument.OutgoingMessagesSent()
			case <-s.HaltCh():
				return
			default:
				if s.disableDecoys {
					instrument.OutgoingQueueLength(s.peerName, len(s.in))
					continue
				}
				toSend = &commands.ReplicaDecoy{
					Cmds: s.commands,
				}
				instrument.OutgoingDecoysSent()
			}
			instrument.OutgoingQueueLength(s.peerName, len(s.in))
			if toSend != nil {
				select {
				case s.out <- toSend:
				case <-s.HaltCh():
					return
				}
			}
		}
	}
}

func (s *outgoingSender) UpdateConnectionStatus(isConnected bool) {
	s.sendQueryOrDecoy.UpdateConnectionStatus(isConnected)
}

func (s *outgoingSender) UpdateRate(rate, maxDelay uint64) error {
	if rate <= 0 {
		return fmt.Errorf("invalid rate: %v", rate)
	}
	s.sendQueryOrDecoy.UpdateRate(rate, maxDelay)
	return nil
}
