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
	"time"

	"github.com/katzenpost/client/constants"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
)

type workerOp interface{}

type opConnStatusChanged struct {
	isConnected bool
}

type opNewDocument struct {
	doc *pki.Document
}

func (s *Session) connStatusChange(op opConnStatusChanged) bool {
	isConnected := op.isConnected
	if isConnected {
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
	// The PKI doc should be cached since we've
	// already waited until we received it.
	doc := s.minclient.CurrentDocument()
	if doc == nil {
		s.fatalErrCh <- errors.New("aborting, PKI doc is nil")
		return
	}

	// LambdaP timer setup
	lambdaP := doc.LambdaP
	lambdaPMsec := uint64(rand.Exp(mRng, lambdaP))
	if lambdaPMsec > doc.LambdaPMaxDelay {
		lambdaPMsec = doc.LambdaPMaxDelay
	}
	lambdaPInterval := time.Duration(lambdaPMsec) * time.Millisecond
	lambdaPTimer := time.NewTimer(lambdaPInterval)
	defer lambdaPTimer.Stop()

	// LambdaL timer setup
	lambdaL := doc.LambdaL
	lambdaLMsec := uint64(rand.Exp(mRng, lambdaL))
	if lambdaLMsec > doc.LambdaLMaxDelay {
		lambdaLMsec = doc.LambdaLMaxDelay
	}
	lambdaLInterval := time.Duration(lambdaLMsec) * time.Millisecond
	lambdaLTimer := time.NewTimer(lambdaLInterval)
	defer lambdaLTimer.Stop()

	// LambdaD timer setup
	lambdaD := doc.LambdaD
	lambdaDMsec := uint64(rand.Exp(mRng, lambdaD))
	if lambdaDMsec > doc.LambdaDMaxDelay {
		lambdaDMsec = doc.LambdaDMaxDelay
	}
	lambdaDInterval := time.Duration(lambdaDMsec) * time.Millisecond
	lambdaDTimer := time.NewTimer(lambdaDInterval)
	defer lambdaDTimer.Stop()

	defer s.log.Debug("session worker halted")

	isConnected := false
	mustResetAllTimers := false
	for {
		var lambdaPFired bool
		var lambdaLFired bool
		var lambdaDFired bool
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
				mustResetAllTimers = true
			default:
				s.log.Warningf("BUG: Worker received nonsensical op: %T", op)
			} // end of switch
		} else {
			if isConnected {
				if lambdaPFired {
					s.sendFromQueueOrDecoy()
				} else if lambdaLFired && !s.cfg.Debug.DisableDecoyTraffic {
					s.sendLoopDecoy()
				} else if lambdaDFired && !s.cfg.Debug.DisableDecoyTraffic {
					s.sendDropDecoy()
				}
			}
		}
		if isConnected {
			lambdaPMsec := uint64(rand.Exp(mRng, lambdaP))
			if lambdaPMsec > doc.LambdaPMaxDelay {
				lambdaPMsec = doc.LambdaPMaxDelay
			}
			lambdaPInterval = time.Duration(lambdaPMsec) * time.Millisecond
			lambdaLMsec := uint64(rand.Exp(mRng, lambdaL))
			if lambdaLMsec > doc.LambdaLMaxDelay {
				lambdaLMsec = doc.LambdaLMaxDelay
			}
			lambdaLInterval = time.Duration(lambdaLMsec) * time.Millisecond
			lambdaDMsec := uint64(rand.Exp(mRng, lambdaD))
			if lambdaDMsec > doc.LambdaDMaxDelay {
				lambdaDMsec = doc.LambdaDMaxDelay
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

func (s *Session) sendFromQueueOrDecoy() {
	// Attempt to send user data first, if any exists.
	// Otherwise send a drop decoy message.
	_, err := s.egressQueue.Peek()
	if err == nil {
		s.sendNext()
	} else if !s.cfg.Debug.DisableDecoyTraffic {
		s.sendDropDecoy()
	}
}

func (s *Session) isDocValid(doc *pki.Document) error {
	for _, provider := range doc.Providers {
		_, ok := provider.Kaetzchen[constants.LoopService]
		if !ok {
			return errors.New("found a Provider which does not have the loop service")
		}
	}
	return nil
}
