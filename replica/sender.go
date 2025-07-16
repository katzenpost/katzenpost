// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/worker"
)

// senderRequest represents a command to send to a peer
type senderRequest struct {
	ReplicaDecoy        *commands.ReplicaDecoy
	ReplicaWriteReply   *commands.ReplicaWriteReply
	ReplicaMessageReply *commands.ReplicaMessageReply
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

// sender is essentially a channel pipeline from "in" to "out" channels where
// the delay between sending is controlled by an exponential distribution
// and we always send something every time the exponential distribution ticks.
// if there are no messages within the "in" channel then we send a decoy message.
type sender struct {
	worker.Worker

	log              *logging.Logger
	in               chan *senderRequest
	out              chan *senderRequest
	sendQueryOrDecoy *common.ExpDist
	disableDecoys    bool

	commands *commands.Commands
}

// newSender starts it's worker but does nothing by default until
// methods UpdateConnectionStatus and UpdateRates are called.
// The worker only works when we have a connection and when we have
// a rate set.
func newSender(in chan *senderRequest, out chan *senderRequest, disableDecoys bool, logBackend *log.Backend, commands *commands.Commands) *sender {
	s := &sender{
		log:              logBackend.GetLogger("replica/sender"),
		in:               in,
		out:              out,
		sendQueryOrDecoy: common.NewExpDist(),
		disableDecoys:    disableDecoys,
		commands:         commands,
	}
	s.Go(s.worker)
	return s
}

// halt is called by the worker() routine when it exits
func (s *sender) halt() {
	s.log.Debug("sender stopping ExpDist worker")
	s.sendQueryOrDecoy.Halt()
}

func (s *sender) worker() {
	defer s.halt() // shutdown expdist workers on return after read from HaltCh()
	for {
		select {
		case <-s.HaltCh():
			return
		case <-s.sendQueryOrDecoy.OutCh():
			var toSend *senderRequest
			select {
			case toSend = <-s.in:
			case <-s.HaltCh():
				return
			default:
				if s.disableDecoys {
					continue
				}
				toSend = &senderRequest{
					ReplicaDecoy: &commands.ReplicaDecoy{
						Cmds: s.commands,
					},
				}
			}
			select {
			case s.out <- toSend:
			case <-s.HaltCh():
				return
			}
		case <-s.HaltCh():
			return
		}
	}
}

func (s *sender) UpdateConnectionStatus(isConnected bool) {
	s.sendQueryOrDecoy.UpdateConnectionStatus(isConnected)
}

func (s *sender) UpdateRate(rate, maxDelay uint64) {
	if rate <= 0 {
		s.log.Warning("Invalid queryOrDecoy rate, using default")
		return
	}
	s.sendQueryOrDecoy.UpdateRate(rate, maxDelay)
}
