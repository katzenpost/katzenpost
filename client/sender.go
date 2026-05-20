// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/worker"
)

// sender drives the Loopix-shaped cover-traffic pair of Poisson processes
// for a single gateway connection.
//
// sendMessageOrLoop ticks at LambdaP: each tick emits either a real
// request drawn from the listener's round-robin scheduler or, if no
// client has queued work, a loop decoy fallback.
//
// sendLoop ticks at LambdaL: each tick emits a loop decoy
// unconditionally, providing the Loopix "loop traffic" cover stream
// independent of the FIFO state.
//
// With disableDecoys set, the LambdaP ticker still fires but emits
// only real requests (no fallback), and the LambdaL ticker is muted
// at the select level so no cover traffic is produced.
type sender struct {
	worker.Worker

	log *logging.Logger

	// pickNext is called once per LambdaP tick to select the next real
	// request to send. Returning nil means "no client has queued work"
	// and the sender falls back to a loop decoy unless decoys are
	// disabled. Provided by the listener's round-robin scheduler in
	// production; stubbed in tests.
	pickNext func() *Request
	out      chan *Request

	sendMessageOrLoop *common.ExpDist // LambdaP: real-or-loop-decoy
	sendLoop          *common.ExpDist // LambdaL: loop-decoy only

	disableDecoys bool
}

// newSender starts the sender's worker but does nothing by default
// until UpdateConnectionStatus and UpdateRates are called. The worker
// only emits when we have a connection and when a non-zero rate has
// been set for the corresponding ExpDist.
func newSender(pickNext func() *Request, out chan *Request, disableDecoys bool, logBackend *log.Backend) *sender {
	s := &sender{
		log:               logBackend.GetLogger("client/sender"),
		pickNext:          pickNext,
		out:               out,
		sendMessageOrLoop: common.NewExpDist(),
		sendLoop:          common.NewExpDist(),
		disableDecoys:     disableDecoys,
	}
	s.Go(s.worker)
	return s
}

// halt is called by the worker() routine when it exits.
func (s *sender) halt() {
	s.log.Debug("sender stopping ExpDist workers")
	s.sendMessageOrLoop.Halt()
	s.sendLoop.Halt()
}

func (s *sender) worker() {
	defer s.halt() // shutdown expdist workers on return after read from HaltCh()

	// When decoys are disabled the LambdaL ticker has no useful work
	// to do; mute its channel so the select never wakes for it. A nil
	// channel in a select arm is never ready.
	loopCh := s.sendLoop.OutCh()
	if s.disableDecoys {
		loopCh = nil
	}

	for {
		select {
		case <-s.sendMessageOrLoop.OutCh():
			s.pickAndSend()
		case <-loopCh:
			s.sendLoopDecoy()
		case <-s.HaltCh():
			return
		}
	}
}

// pickAndSend fills one LambdaP slot. Extracted so tests can drive the
// scheduler-plus-decoy path without firing a real exponential timer.
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

// sendLoopDecoy fills one LambdaL slot with a loop decoy.
func (s *sender) sendLoopDecoy() {
	select {
	case s.out <- newLoopDecoy():
	case <-s.HaltCh():
	}
}

func (s *sender) UpdateConnectionStatus(isConnected bool) {
	s.sendMessageOrLoop.UpdateConnectionStatus(isConnected)
	s.sendLoop.UpdateConnectionStatus(isConnected)
}

func (s *sender) UpdateRates(rates *Rates) {
	if rates.messageOrLoop <= 0 {
		s.log.Warning("Invalid messageOrLoop rate, ignoring")
		return
	}
	s.sendMessageOrLoop.UpdateRate(uint64(1/rates.messageOrLoop), rates.messageOrLoopMaxDelay)

	// The LambdaL ticker stays dormant until a positive rate is
	// published, so a PKI document that omits LambdaL produces no
	// loop-decoy ticks.
	if rates.loop > 0 {
		s.sendLoop.UpdateRate(uint64(1/rates.loop), rates.loopMaxDelay)
	}
}

func newLoopDecoy() *Request {
	return &Request{
		SendLoopDecoy: &SendLoopDecoy{},
	}
}
