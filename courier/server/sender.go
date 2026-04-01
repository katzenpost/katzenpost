// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/courier/server/instrument"
)

// courierSenderRequest represents a command to send to a replica, either a
// real message or a decoy.
type courierSenderRequest struct {
	ReplicaMessage *commands.ReplicaMessage
	ReplicaDecoy   *commands.ReplicaDecoy
}

func (r *courierSenderRequest) command() commands.Command {
	if r.ReplicaMessage != nil {
		return r.ReplicaMessage
	}
	if r.ReplicaDecoy != nil {
		return r.ReplicaDecoy
	}
	return nil
}

// sender sits between the dispatch channel and the wire for a single replica
// connection, interleaving decoy messages when no real traffic is available.
// The send rate is governed by an exponential distribution.
type sender struct {
	worker.Worker

	log              *logging.Logger
	in               chan *courierSenderRequest
	out              chan *courierSenderRequest
	sendQueryOrDecoy *common.ExpDist
	disableDecoys    bool
	replicaName      string

	commands *commands.Commands
}

// newSender creates a sender and starts its worker goroutine. It remains idle
// until UpdateRate and UpdateConnectionStatus(true) are called.
func newSender(in chan *courierSenderRequest, out chan *courierSenderRequest, disableDecoys bool, logBackend *log.Backend, cmds *commands.Commands, replicaName string) *sender {
	s := &sender{
		log:              logBackend.GetLogger("courier/sender"),
		in:               in,
		out:              out,
		sendQueryOrDecoy: common.NewExpDist(),
		disableDecoys:    disableDecoys,
		commands:         cmds,
		replicaName:      replicaName,
	}
	s.Go(s.worker)
	return s
}

func (s *sender) halt() {
	s.log.Debug("sender stopping ExpDist worker")
	s.sendQueryOrDecoy.Halt()
}

func (s *sender) worker() {
	defer s.halt()
	for {
		select {
		case <-s.HaltCh():
			return
		case <-s.sendQueryOrDecoy.OutCh():
			var toSend *courierSenderRequest
			select {
			case toSend = <-s.in:
				instrument.MessagesSent()
				instrument.QueueLength(s.replicaName, len(s.in))
			case <-s.HaltCh():
				return
			default:
				// No real message - send decoy if enabled.
				if s.disableDecoys {
					continue
				}
				toSend = &courierSenderRequest{
					ReplicaDecoy: &commands.ReplicaDecoy{
						Cmds: s.commands,
					},
				}
				instrument.DecoysSent()
			}
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

func (s *sender) UpdateConnectionStatus(isConnected bool) {
	s.sendQueryOrDecoy.UpdateConnectionStatus(isConnected)
}

func (s *sender) UpdateRate(rate, maxDelay uint64) error {
	if rate <= 0 {
		return fmt.Errorf("invalid rate: %v", rate)
	}
	s.sendQueryOrDecoy.UpdateRate(rate, maxDelay)
	return nil
}
