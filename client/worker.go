// worker.go - mixnet client worker
// Copyright (C) 2018, 2019  David Stainton
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

package client

import (
	"errors"
	"math"
	mrand "math/rand"
	"time"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/client/utils"
	"github.com/katzenpost/katzenpost/core/pki"
)

type workerOp interface{}

type opConnStatusChanged struct {
	isConnected bool
}

type opNewDocument struct {
	doc *pki.Document
}

type opRetransmit struct {
	msg *Message
}

func (s *Session) connStatusChange(op opConnStatusChanged) bool {
	isConnected := op.isConnected
	if isConnected {
		// If we have awoken from suspend and there is no
		// current consensus, attempt to fetch one immediately.
		if doc := s.minclient.CurrentDocument(); doc == nil {
			s.minclient.ForceFetchPKI()
		}
		s.onlineAt = time.Now()

		skew := s.minclient.ClockSkew()
		absSkew := skew
		if absSkew < 0 {
			absSkew = -absSkew
		}
		if absSkew > constants.TimeSkewWarnDelta {
			// Should this do more than just warn?  Should this
			// use skewed time?  I don't know.
			s.log.Warningf("The observed time difference between the host and provider clocks is '%v'. Correct your system time.", skew)
		} else {
			s.log.Debugf("Clock skew vs provider: %v", skew)
		}
	}
	return isConnected
}

func (s *Session) worker() {
	const maxDuration = math.MaxInt64
	mRng := rand.NewMath()

	// get the initial loop services if decoy traffic is enabled
	var (
		doc             *pki.Document
		loopServices    []utils.ServiceDescriptor
		lambdaP         float64
		lambdaL         float64
		lambdaD         float64
		lambdaPMsec     uint64
		lambdaLMsec     uint64
		lambdaDMsec     uint64
		lambdaPTimer    = time.NewTimer(maxDuration)
		lambdaLTimer    = time.NewTimer(maxDuration)
		lambdaDTimer    = time.NewTimer(maxDuration)
		lambdaPInterval = time.Duration(maxDuration)
		lambdaLInterval = time.Duration(maxDuration)
		lambdaDInterval = time.Duration(maxDuration)
		lambdaPMaxDelay = uint64(maxDuration)
		lambdaLMaxDelay = uint64(maxDuration)
		lambdaDMaxDelay = uint64(maxDuration)
	)

	defer s.log.Debug("session worker halted")
	defer lambdaPTimer.Stop()
	defer lambdaLTimer.Stop()
	defer lambdaDTimer.Stop()

	isConnected := false
	mustResetAllTimers := false
	for {
		var lambdaPFired bool
		var lambdaLFired bool
		var lambdaDFired bool
		var loopSvc *utils.ServiceDescriptor
		var qo workerOp

		select {
		case <-s.HaltCh():
			s.log.Debugf("Session worker terminating gracefully.")
			return
		case <-lambdaPTimer.C:
			lambdaPFired = true
		case <-lambdaLTimer.C:
			lambdaLFired = true
		case <-lambdaDTimer.C:
			lambdaDFired = true
		case qo = <-s.opCh:
		}

		if qo != nil {
			switch op := qo.(type) {
			case opRetransmit:
				s.doRetransmit(op.msg)
			case opConnStatusChanged:
				newConnectedStatus := s.connStatusChange(op)
				isConnected = newConnectedStatus
				mustResetAllTimers = true
			case opNewDocument:
				err := s.isDocValid(op.doc)
				if err != nil {
					s.fatalErrCh <- err
				}

				doc = op.doc
				lambdaP = doc.LambdaP
				lambdaL = doc.LambdaL
				lambdaD = doc.LambdaD

				// update the loop service descriptors
				loopServices = utils.FindServices(constants.LoopService, doc)
				if len(loopServices) == 0 {
					s.fatalErrCh <- errors.New("failure to get loop service")
					return
				}

				mustResetAllTimers = true
			default:
				s.log.Warningf("BUG: Worker received nonsensical op: %T", op)
			} // end of switch
		} else {
			if isConnected {
				// select a loop service endpoint
				if !s.cfg.Debug.DisableDecoyTraffic {
					loopSvc = &loopServices[mrand.Intn(len(loopServices))]
				}
				if lambdaPFired {
					s.sendFromQueueOrDecoy(loopSvc)
				} else if lambdaLFired && !s.cfg.Debug.DisableDecoyTraffic {
					s.sendLoopDecoy(loopSvc)
				} else if lambdaDFired && !s.cfg.Debug.DisableDecoyTraffic {
					s.sendDropDecoy(loopSvc)
				}
			}
		}
		if isConnected && doc != nil {
			lambdaPMsec = uint64(rand.Exp(mRng, lambdaP))
			if lambdaPMsec > lambdaPMaxDelay {
				lambdaPMsec = lambdaPMaxDelay
			}
			lambdaPInterval = time.Duration(lambdaPMsec) * time.Millisecond
			lambdaLMsec = uint64(rand.Exp(mRng, lambdaL))
			if lambdaLMsec > lambdaLMaxDelay {
				lambdaLMsec = lambdaLMaxDelay
			}
			lambdaLInterval = time.Duration(lambdaLMsec) * time.Millisecond
			lambdaDMsec = uint64(rand.Exp(mRng, lambdaD))
			if lambdaDMsec > lambdaDMaxDelay {
				lambdaDMsec = lambdaDMaxDelay
			}
			lambdaDInterval = time.Duration(lambdaDMsec) * time.Millisecond
		} else {
			lambdaLInterval = time.Duration(maxDuration)
			lambdaPInterval = time.Duration(maxDuration)
			lambdaDInterval = time.Duration(maxDuration)
		}

		if mustResetAllTimers {
			lambdaPTimer.Reset(lambdaPInterval)
			lambdaLTimer.Reset(lambdaLInterval)
			lambdaDTimer.Reset(lambdaDInterval)
			mustResetAllTimers = false
		} else {
			// reset only the timer that fired
			if lambdaPFired {
				lambdaPTimer.Reset(lambdaPInterval)
			}
			if lambdaLFired {
				lambdaLTimer.Reset(lambdaLInterval)
			}
			if lambdaDFired {
				lambdaDTimer.Reset(lambdaDInterval)
			}
		}
	}

	// NOTREACHED
}

func (s *Session) sendFromQueueOrDecoy(loopSvc *utils.ServiceDescriptor) {
	// Attempt to send user data first, if any exists.
	// Otherwise send a drop decoy message.
	_, err := s.egressQueue.Peek()
	if err == nil {
		s.sendNext()
	} else if !s.cfg.Debug.DisableDecoyTraffic {
		s.sendDropDecoy(loopSvc)
	}
}

func (s *Session) isDocValid(doc *pki.Document) error {
	for _, provider := range doc.ServiceNodes {
		_, ok := provider.Services[constants.LoopService]
		if ok {
			return nil
		}
	}
	return errors.New("found no provider with the loop service")
}
