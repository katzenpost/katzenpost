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

func (s *Session) setTimers(doc *pki.Document) {
	// λP
	pDesc := &poisson.Descriptor{
		Lambda: doc.SendLambda,
		Max:    doc.SendMaxInterval,
	}
	if s.pTimer == nil {
		s.pTimer = poisson.NewTimer(pDesc)
	} else {
		s.pTimer.SetPoisson(pDesc)
	}
}

func (s *Session) connStatusChange(op opConnStatusChanged) bool {
	isConnected := false
	if isConnected = op.isConnected; isConnected {
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

	var isConnected bool
	for {
		var lambdaPFired bool
		var qo workerOp
		select {
		case <-s.HaltCh():
			s.log.Debugf("Terminating gracefully.")
			return
		case <-s.pTimer.Timer.C:
			lambdaPFired = true
		case qo = <-s.opCh:
		}
		if isConnected {
			if lambdaPFired {
				s.lambdaPTask()
			}
		}
		if qo != nil {
			switch op := qo.(type) {
			case opIsEmpty:
				// XXX do cleanup here?
				continue
			case opConnStatusChanged:
				// Note: s.isConnected isn't used in favor of passing the
				// value via an op, to save on locking headaches.
				isConnected = s.connStatusChange(op)
			case opNewDocument:
				s.maybeUpdateTimers(op.doc)
			default:
				s.log.Warningf("BUG: Worker received nonsensical op: %T", op)
			} // end of switch
		} // if qo != nil

		if lambdaPFired {
			s.pTimer.Next()
		}
	}

	// NOTREACHED
}

func (s *Session) lambdaPTask() {
	// Attempt to send user data first, if any exists.
	// Otherwise send a drop decoy message.
	err := s.sendNext()
	if err != nil {
		s.log.Warningf("Failed to send queued message: %v", err)
		err = s.sendLoopDecoy()
		if err != nil {
			s.log.Warningf("Failed to send loop decoy traffic: %v", err)
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
