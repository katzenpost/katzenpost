// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/worker"
)

type sender struct {
	worker.Worker

	log *logging.Logger

	in  chan *Request
	out chan *Request

	sendMessageOrLoop *common.ExpDist

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
		sendMessageOrLoop: common.NewExpDist(),
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
	if rates.messageOrLoop <= 0 {
		s.log.Warning("Invalid messageOrDrop rate, using default")
		return
	}
	s.sendMessageOrLoop.UpdateRate(uint64(1/rates.messageOrLoop), rates.messageOrLoopMaxDelay)
}

func newLoopDecoy() *Request {
	return &Request{
		SendLoopDecoy: &SendLoopDecoy{},
	}
}
