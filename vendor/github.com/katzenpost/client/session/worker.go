// worker.go - mixnet client worker
// Copyright (C) 2018  David Stainton.
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

package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/katzenpost/client/poisson"
	"github.com/katzenpost/core/pki"
)

type workerOp interface{}

type opIsEmpty struct{}

type opConnStatusChanged struct {
	isConnected bool
}

type opNewDocument struct {
	doc *pki.Document
}

func (s *Session) setPollingInterval(doc *pki.Document) {
	// Clients have 3 poisson processes, λP, λL and, λD.
	// However only LambdaP and LambdaL result in SURB replies.
	interval := time.Duration(doc.LambdaP+doc.LambdaL) * time.Millisecond
	s.minclient.SetPollInterval(interval)
}

func (s *Session) setTimers(doc *pki.Document) {
	// λP
	pDesc := &poisson.Descriptor{
		Lambda: doc.LambdaP,
		Max:    doc.LambdaPMaxDelay,
	}
	if s.pTimer == nil {
		s.pTimer = poisson.NewTimer(pDesc)
	} else {
		s.pTimer.SetPoisson(pDesc)
	}

	// λL
	lDesc := &poisson.Descriptor{
		Lambda: doc.LambdaL,
		Max:    doc.LambdaLMaxDelay,
	}
	if s.lTimer == nil {
		s.lTimer = poisson.NewTimer(lDesc)
	} else {
		s.lTimer.SetPoisson(lDesc)
	}

	// λD
	dDesc := &poisson.Descriptor{
		Lambda: doc.LambdaD,
		Max:    doc.LambdaDMaxDelay,
	}
	if s.dTimer == nil {
		s.dTimer = poisson.NewTimer(dDesc)
	} else {
		s.dTimer.SetPoisson(dDesc)
	}
}

func (s *Session) connStatusChange(op opConnStatusChanged) bool {
	isConnected := op.isConnected
	if isConnected {
		const skewWarnDelta = 2 * time.Minute
		s.onlineAt = time.Now()

		skew := s.minclient.ClockSkew()
		absSkew := skew
		if absSkew < 0 {
			absSkew = -absSkew
		}
		if absSkew > skewWarnDelta {
			// Should this do more than just warn?  Should this
			// use skewed time?  I don't know.
			s.log.Warningf("The observed time difference between the host and provider clocks is '%v'. Correct your system time.", skew)
		} else {
			s.log.Debugf("Clock skew vs provider: %v", skew)
		}
	}
	return isConnected
}

func (s *Session) maybeUpdateTimers(doc *pki.Document) {
	// Determine if PKI doc is valid. If not then abort.
	err := s.isDocValid(doc)
	if err != nil {
		s.log.Errorf("Aborting, PKI doc is not valid for the Loopix decoy traffic use case: %v", err)
		s.fatalErrCh <- fmt.Errorf("Aborting, PKI doc is not valid for the Loopix decoy traffic use case: %v", err)
		return
	}
	s.setTimers(doc)
}

// worker performs work. It runs in it's own goroutine
// and implements a shutdown code path as well.
// This function assumes the timers are setup but
// not yet started.
func (s *Session) worker() {
	s.pTimer.Start()
	defer s.pTimer.Stop()
	s.dTimer.Start()
	defer s.dTimer.Stop()
	s.lTimer.Start()
	defer s.lTimer.Stop()

	var isConnected bool
	for {
		var lambdaPFired bool
		var lambdaDFired bool
		var lambdaLFired bool
		var qo workerOp
		select {
		case <-s.HaltCh():
			s.log.Debugf("Terminating gracefully.")
			return
		case <-s.pTimer.Timer.C:
			lambdaPFired = true
		case <-s.dTimer.Timer.C:
			lambdaDFired = true
		case <-s.lTimer.Timer.C:
			lambdaLFired = true
		case qo = <-s.opCh:
		}

		if lambdaPFired {
			if isConnected {
				s.sendFromQueueOrDecoy()
			}
		}
		if lambdaDFired {
			if isConnected {
				err := s.sendDropDecoy()
				if err != nil {
					s.log.Error(err.Error())
				}
			}
		}
		if lambdaLFired {
			if isConnected {
				err := s.sendLoopDecoy()
				if err != nil {
					s.log.Error(err.Error())
				}
			}
		}
		if qo != nil {
			switch op := qo.(type) {
			case opIsEmpty:
				// XXX do periodic cleanup here
				continue
			case opConnStatusChanged:
				isConnected = s.connStatusChange(op)
			case opNewDocument:
				s.setPollingInterval(op.doc)
				s.maybeUpdateTimers(op.doc)
			default:
				s.log.Warningf("BUG: Worker received nonsensical op: %T", op)
			} // end of switch
		}

		if lambdaPFired {
			s.pTimer.Next()
		}
		if lambdaDFired {
			s.dTimer.Next()
		}
		if lambdaLFired {
			s.lTimer.Next()
		}

	}

	// NOTREACHED
}

func (s *Session) sendFromQueueOrDecoy() {
	// Attempt to send user data first, if any exists.
	// Otherwise send a drop decoy message.
	_, err := s.egressQueue.Peek()
	if err == nil {
		err := s.sendNext()
		if err != nil {
			panic(err)
		}
	} else {
		if !s.cfg.Debug.DisableDecoyLoops {
			err = s.sendDropDecoy()
			if err != nil {
				s.log.Warningf("Failed to send loop decoy traffic: %v", err)
			}
		}
	}
}

func (s *Session) isDocValid(doc *pki.Document) error {
	const serviceLoop = "loop"
	for _, provider := range doc.Providers {
		_, ok := provider.Kaetzchen[serviceLoop]
		if !ok {
			return errors.New("Error, found a Provider which does not have the loop service.")
		}
	}
	return nil
}
