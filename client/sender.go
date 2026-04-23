// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/worker"
)

type sender struct {
	worker.Worker

	log *logging.Logger

	// pickNext is called once per Poisson tick to select the next request
	// to send. Returning nil means "no client has queued work" and the
	// sender falls back to a loop decoy (unless decoys are disabled).
	// Provided by the listener's round-robin scheduler in production;
	// stubbed in tests.
	pickNext func() *Request
	out      chan *Request

	sendMessageOrLoop *common.ExpDist

	disableDecoys bool
}

// newSender starts it's worker but does nothing by default until
// methods UpdateConnectionStatus and UpdateRates are called.
// The worker only works when we have a connection and when we have
// a rate set.
func newSender(pickNext func() *Request, out chan *Request, disableDecoys bool, logBackend *log.Backend) *sender {
	s := &sender{
		log:               logBackend.GetLogger("client/sender"),
		pickNext:          pickNext,
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
			s.pickAndSend()
		case <-s.HaltCh():
			return
		}
	}
}

// pickAndSend fills one Poisson send slot. Extracted so tests can drive the
// scheduler-plus-decoy path without firing a real exponential-distribution
// timer.
func (s *sender) pickAndSend() {
	toSend := s.pickNext()
	if toSend == nil {
		if s.disableDecoys {
			return
		}
		toSend = newLoopDecoy()
	}
	select {
	case s.out <- toSend:
	case <-s.HaltCh():
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
