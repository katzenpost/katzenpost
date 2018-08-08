// worker.go - mixnet client worker
// Copyright (C) 2018  Yawning Angel, David Stainton.
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
	"math"
	"time"

	"github.com/katzenpost/core/crypto/rand"
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

func (c *Client) worker() {
	const (
		maxDuration  = math.MaxInt64
		minSendShift = 1000 // 1 second.
		serviceLoop  = "loop"
	)

	// Intentionally use super conservative values for the send scheduling
	// if the PKI happens to not specify any.
	sendLambda := 0.00001
	sendShift := uint64(60000)
	sendMaxInterval := uint64(rand.ExpQuantile(sendLambda, 0.99999))

	mRng := rand.NewMath()
	wakeInterval := time.Duration(maxDuration)
	timer := time.NewTimer(wakeInterval)
	defer timer.Stop()

	var isConnected bool
	for {
		var timerFired bool
		var qo workerOp
		select {
		case <-c.HaltCh():
			return
		case <-timer.C:
			timerFired = true
			// XXX case qo = <-a.opCh:
		}
		if timerFired {
			// It is time to send another block if one exists.
			if isConnected { // Suppress spurious wakeups.
				// Attempt to send user data first, if any exists.
				didSend, err := c.sendNext()
				if err != nil {
					c.log.Warningf("Failed to send queued message: %v", err)
				} else if !didSend {
					// Send drop decoy message instead.
					err = c.sendDropDecoy()
					if err != nil {
						c.log.Warningf("Failed to send drop decoy traffic: %v", err)
					}
				}
			} // if isConnected
		} else {
			switch op := qo.(type) {
			case *opIsEmpty:
				// XXX do cleanup here?
				continue
			case *opConnStatusChanged:
				// Note: a.isConnected isn't used in favor of passing the
				// value via an op, to save on locking headaches.
				if isConnected = op.isConnected; isConnected {
					const skewWarnDelta = 2 * time.Minute
					c.onlineAt = time.Now()

					skew := c.minclient.ClockSkew()
					absSkew := skew
					if absSkew < 0 {
						absSkew = -absSkew
					}
					if absSkew > skewWarnDelta {
						// Should this do more than just warn?  Should this
						// use skewed time?  I don't know.
						c.log.Warningf("The observed time difference between the host and provider clocks is '%v'.  Correct your system time.", skew)
					} else {
						c.log.Debugf("Clock skew vs provider: %v", skew)
					}
				}
			case *opNewDocument:
				// Update the Send[Lambda,Shift,MaxInterval] parameters from
				// the PKI document.
				if newSendLambda := op.doc.SendLambda; newSendLambda != sendLambda {
					c.log.Debugf("Updated SendLambda: %v", newSendLambda)
					sendLambda = newSendLambda
				}
				if newSendShift := op.doc.SendShift; newSendShift != sendShift {
					if newSendShift < minSendShift {
						c.log.Debugf("Ignoring pathologically small SendShift: %v", newSendShift)
					} else {
						c.log.Debugf("Updated SendShift: %v", newSendShift)
						sendShift = newSendShift
					}
				}
				if newSendMaxInterval := op.doc.SendMaxInterval; newSendMaxInterval != sendMaxInterval {
					c.log.Debugf("Updated SendMaxInterval: %v", newSendMaxInterval)
					sendMaxInterval = newSendMaxInterval
				}

				// Determine if it is possible to send cover traffic.
				err := c.isDocValid(op.doc, c.cfg.Debug.EnableLoops)
				if err != nil {
					c.log.Errorf("Aborting... PKI Document is not valid for our use case: %v", err)
					return
				}
			default:
				c.log.Warningf("BUG: Worker received nonsensical op: %T", op)
			}
		}
		if isConnected {
			// Per section 4.1.2 of the Loopix paper:
			//
			//   Users emit payload messages following a Poisson
			//   distribution with parameter lambdaP. All messages
			//   scheduled for sending by the user are placed within
			//   a first-in first-out buffer. According to a Poisson
			//   process, a single message is popped out of the buffer
			//   and sent, or a drop cover message is sent in case the
			//   buffer is empty. Thus, from an adversarial perspective,
			//   there is always traffic emitted modeled by Pois(lambdaP).
			wakeMsec := uint64(rand.Exp(mRng, sendLambda))
			switch {
			case wakeMsec > sendMaxInterval:
				wakeMsec = sendMaxInterval
			default:
			}
			wakeMsec += sendShift // Sample, clamp, then shift.

			wakeInterval = time.Duration(wakeMsec) * time.Millisecond
			c.log.Debugf("wakeInterval: %v", wakeInterval)
		} else {
			wakeInterval = maxDuration
		}
		if !timerFired && !timer.Stop() {
			<-timer.C
		}
		timer.Reset(wakeInterval)
	} // for
}

func (c *Client) isDocValid(doc *pki.Document, sendLoops bool) error {
	return nil // XXX fix me
}
