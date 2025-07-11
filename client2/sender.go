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

	sendMessageOrDrop *ExpDist
	sendDrop          *ExpDist
	sendLoop          *ExpDist

	disableDecoys bool
}

// newSender starts it's worker but does nothing by default until
// methods UpdateConnectionStatus and UpdateRates are called.
// The worker only works when we have a connection and when we have
// a rate set.
func newSender(in chan *Request, out chan *Request, disableDecoys bool, logBackend *log.Backend) *sender {
	s := &sender{
		log:               logBackend.GetLogger("client2/daemon"),
		in:                in,
		out:               out,
		sendMessageOrDrop: NewExpDist(),
		sendLoop:          NewExpDist(),
		sendDrop:          NewExpDist(),
		disableDecoys:     disableDecoys,
	}
	s.Go(s.worker)
	return s
}

// halt is called by the worker() routine when it exits
func (s *sender) halt() {
	s.log.Debug("sender stopping ExpDist workers")
	s.sendMessageOrDrop.Halt()
	s.log.Debug("sendMessageOrDrop stopped")
	s.sendLoop.Halt()
	s.log.Debug("sendLoop stopped")
	s.sendDrop.Halt()
	s.log.Debug("sendDrop stopped")
}

func (s *sender) worker() {
	dropDecoyCh := s.sendDrop.OutCh()
	loopDecoyCh := s.sendLoop.OutCh()
	if s.disableDecoys {
		loopDecoyCh = make(<-chan struct{})
		dropDecoyCh = make(<-chan struct{})
	}
	defer s.halt() // shutdown expdist workers on return after read from HaltCh()
	for {
		select {
		case <-s.sendMessageOrDrop.OutCh():
			var toSend *Request
			select {
			case toSend = <-s.in:
			case <-s.HaltCh():
				return
			default:
				if s.disableDecoys {
					continue
				}
				toSend = newDropDecoy()
			}
			select {
			case s.out <- toSend:
			case <-s.HaltCh():
				return
			}
		case <-loopDecoyCh:
			toSend := newLoopDecoy()
			select {
			case s.out <- toSend:
			case <-s.HaltCh():
				return
			}
		case <-dropDecoyCh:
			toSend := newDropDecoy()
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
	s.sendMessageOrDrop.UpdateConnectionStatus(isConnected)
	s.sendLoop.UpdateConnectionStatus(isConnected)
	s.sendDrop.UpdateConnectionStatus(isConnected)
}

func (s *sender) UpdateRates(rates *Rates) {
	s.sendMessageOrDrop.UpdateRate(uint64(1/rates.messageOrDrop), rates.messageOrDropMaxDelay)
	s.sendLoop.UpdateRate(uint64(1/rates.loop), rates.loopMaxDelay)
	s.sendDrop.UpdateRate(uint64(1/rates.drop), rates.dropMaxDelay)
}

func newLoopDecoy() *Request {
	return &Request{
		SendLoopDecoy: &SendLoopDecoy{},
	}
}

func newDropDecoy() *Request {
	return &Request{
		SendDropDecoy: &SendDropDecoy{},
	}
}
