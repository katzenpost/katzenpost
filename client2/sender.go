// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/worker"
	"gopkg.in/op/go-logging.v1"
)

type sender struct {
	worker.Worker

	log *logging.Logger

	in  chan *Request
	out chan *Request

	sendMessageOrLoop *ExpDist

	disableDecoys bool
}

// newSender starts it's worker but does nothing by default until
// methods UpdateConnectionStatus and UpdateRates are called.
// The worker only works when we have a connection and when we have
// a rate set.
func newSender(in chan *Request, out chan *Request, disableDecoys bool, logBackend *log.Backend) *sender {
	s := &sender{
		log:               logBackend.GetLogger("client2/sender"),
		in:                in,
		out:               out,
		sendMessageOrLoop: NewExpDist(),
		disableDecoys:     disableDecoys,
	}
	s.Go(s.worker)
	return s
}

// halt is called by the worker() routine when it exits
func (s *sender) halt() {
	s.log.Debug("sender stopping ExpDist worker")
	s.sendMessageOrLoop.Halt()
}

func (s *sender) worker() {
	defer s.halt() // shutdown expdist workers on return after read from HaltCh()
	for {
		select {
		case <-s.sendMessageOrLoop.OutCh():
			var toSend *Request
			select {
			case toSend = <-s.in:
			case <-s.HaltCh():
				return
			default:
				if s.disableDecoys {
					continue
				}
				toSend = newLoopDecoy()
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
	s.sendMessageOrLoop.UpdateConnectionStatus(isConnected)
}

func (s *sender) UpdateRates(rates *Rates) {
	s.sendMessageOrLoop.UpdateRate(uint64(1/rates.messageOrDrop), rates.messageOrDropMaxDelay)
}

func newLoopDecoy() *Request {
	return &Request{
		SendLoopDecoy: &SendLoopDecoy{},
	}
}
