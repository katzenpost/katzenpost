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

func (s *Session) initializeTimers() {

	// Lambda-P will use Lambda-D settings
	// initially until we get the PKI doc.
	pDesc := &poisson.PoissonDescriptor{
		Lambda: s.cfg.Debug.LambdaD,
		Shift:  s.cfg.Debug.LambdaDShift,
		Max:    s.cfg.Debug.LambdaDMax,
	}
	s.pTimer = poisson.NewTimer(pDesc)

	// Lambda-D
	dDesc := &poisson.PoissonDescriptor{
		Lambda: s.cfg.Debug.LambdaD,
		Shift:  s.cfg.Debug.LambdaDShift,
		Max:    s.cfg.Debug.LambdaDMax,
	}
	s.dTimer = poisson.NewTimer(dDesc)

	// Lambda-L
	if s.cfg.Debug.EnableLoops {
		lDesc := &poisson.PoissonDescriptor{
			Lambda: s.cfg.Debug.LambdaL,
			Shift:  s.cfg.Debug.LambdaLShift,
			Max:    s.cfg.Debug.LambdaLMax,
		}
		s.lTimer = poisson.NewTimer(lDesc)
	}
}

func (s *Session) worker() {
	s.initializeTimers()

	s.pTimer.Start()
	defer s.pTimer.Stop()
	s.dTimer.Start()
	defer s.dTimer.Stop()
	var lambdaLChan *<-chan time.Time = new(<-chan time.Time)
	if s.cfg.Debug.EnableLoops {
		s.lTimer.Start()
		defer s.lTimer.Stop()
		*lambdaLChan = s.lTimer.Timer.C
	}
	var isConnected bool = false
	for {
		var lambdaLFired bool = false
		var lambdaDFired bool = false
		var lambdaPFired bool = false
		var qo workerOp = nil
		select {
		case <-s.HaltCh():
			s.log.Debugf("Terminating gracefully.")
			return
		case <-s.pTimer.Timer.C:
			lambdaPFired = true
		case <-s.dTimer.Timer.C:
			lambdaDFired = true
		case <-*lambdaLChan:
			lambdaLFired = true
		case qo = <-s.opCh:
		}
		if isConnected {
			if lambdaPFired {
				s.lambdaPTask()
			}
			if lambdaDFired {
				s.lambdaDTask()
			}
			if lambdaLFired {
				s.lambdaLTask()
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
			case opNewDocument:
				// Determine if PKI doc is valid.
				// If not then abort.
				err := s.isDocValid(op.doc)
				if err != nil {
					s.log.Errorf("Aborting, PKI doc is not valid for the Loopix decoy traffic use case: %v", err)
					s.fatalErrCh <- fmt.Errorf("Aborting, PKI doc is not valid for the Loopix decoy traffic use case: %v", err)
					return
				}

				// Update our Lambda-P parameters from the PKI document
				// if indeed they have changed.
				desc := &poisson.PoissonDescriptor{
					Lambda: op.doc.SendLambda,
					Shift:  op.doc.SendShift,
					Max:    op.doc.SendMaxInterval,
				}
				if !s.pTimer.DescriptorEquals(desc) {
					s.pTimer.SetPoisson(desc)
				}
			default:
				s.log.Warningf("BUG: Worker received nonsensical op: %T", op)
			} // end of switch
		} // if qo != nil

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

func (s *Session) lambdaPTask() {
	// Attempt to send user data first, if any exists.
	// Otherwise send a drop decoy message.
	err := s.sendNext()
	if err != nil {
		s.log.Warningf("Failed to send queued message: %v", err)
		err = s.sendDropDecoy()
		if err != nil {
			s.log.Warningf("Failed to send drop decoy traffic: %v", err)
		}
	}
}

func (s *Session) lambdaDTask() {
	err := s.sendDropDecoy()
	if err != nil {
		s.log.Warningf("Failed to send drop decoy traffic: %v", err)
	}
}

func (s *Session) lambdaLTask() {
	err := s.sendLoopDecoy()
	if err != nil {
		s.log.Warningf("Failed to send drop decoy traffic: %v", err)
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
