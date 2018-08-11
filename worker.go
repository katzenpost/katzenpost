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

package client

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

func (c *Client) initializeTimers() {
	c.WaitForPKIDocument()

	// Lambda-P
	doc := c.minclient.CurrentDocument()
	pDesc := &poisson.PoissonDescriptor{
		Lambda: doc.SendLambda,
		Shift:  doc.SendShift,
		Max:    doc.SendMaxInterval,
	}
	c.pTimer = poisson.NewTimer(pDesc)

	// Lambda-D
	dDesc := &poisson.PoissonDescriptor{
		Lambda: c.cfg.Debug.LambdaD,
		Shift:  c.cfg.Debug.LambdaDShift,
		Max:    c.cfg.Debug.LambdaDMax,
	}
	c.dTimer = poisson.NewTimer(dDesc)

	// Lambda-L
	if c.cfg.Debug.EnableLoops {
		lDesc := &poisson.PoissonDescriptor{
			Lambda: c.cfg.Debug.LambdaL,
			Shift:  c.cfg.Debug.LambdaLShift,
			Max:    c.cfg.Debug.LambdaLMax,
		}
		c.lTimer = poisson.NewTimer(lDesc)
	}
}

func (c *Client) worker() {
	c.initializeTimers()

	c.pTimer.Start()
	defer c.pTimer.Stop()
	c.dTimer.Start()
	defer c.dTimer.Stop()
	var lambdaLChan *<-chan time.Time = new(<-chan time.Time)
	if c.cfg.Debug.EnableLoops {
		c.lTimer.Start()
		defer c.lTimer.Stop()
		*lambdaLChan = c.lTimer.Timer.C
	}
	var isConnected bool = false
	for {
		var lambdaLFired bool = false
		var lambdaDFired bool = false
		var lambdaPFired bool = false
		var qo workerOp = nil
		select {
		case <-c.HaltCh():
			c.log.Debugf("Terminating gracefully.")
			return
		case <-c.pTimer.Timer.C:
			lambdaPFired = true
		case <-c.dTimer.Timer.C:
			lambdaDFired = true
		case <-*lambdaLChan:
			lambdaLFired = true
		case qo = <-c.opCh:
		}
		if isConnected {
			if lambdaPFired {
				c.lambdaPTask()
			}
			if lambdaDFired {
				c.lambdaDTask()
			}
			if lambdaLFired {
				c.lambdaLTask()
			}
		}
		if qo != nil {
			switch op := qo.(type) {
			case opIsEmpty:
				// XXX do cleanup here?
				continue
			case opConnStatusChanged:
				// Note: c.isConnected isn't used in favor of passing the
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
						c.log.Warningf("The observed time difference between the host and provider clocks is '%v'. Correct your system time.", skew)
					} else {
						c.log.Debugf("Clock skew vs provider: %v", skew)
					}
				}
			case opNewDocument:
				// Determine if PKI doc is valid.
				// If not then abort.
				err := c.isDocValid(op.doc)
				if err != nil {
					c.log.Errorf("Aborting, PKI doc is not valid for the Loopix decoy traffic use case: %v", err)
					c.fatalErrCh <- fmt.Errorf("Aborting, PKI doc is not valid for the Loopix decoy traffic use case: %v", err)
					return
				}

				// Update our Lambda-P parameters from the PKI document
				// if indeed they have changed.
				desc := &poisson.PoissonDescriptor{
					Lambda: op.doc.SendLambda,
					Shift:  op.doc.SendShift,
					Max:    op.doc.SendMaxInterval,
				}
				if !c.pTimer.DescriptorEquals(desc) {
					c.pTimer.SetPoisson(desc)
				}
			default:
				c.log.Warningf("BUG: Worker received nonsensical op: %T", op)
			} // end of switch
		} // if qo != nil

		if isConnected {
			if lambdaPFired {
				c.pTimer.Next()
			}
			if lambdaDFired {
				c.dTimer.Next()
			}
			if lambdaLFired {
				c.lTimer.Next()
			}
		}
	}

	// NOTREACHED
}

func (c *Client) lambdaPTask() {
	// Attempt to send user data first, if any exists.
	// Otherwise send a drop decoy message.
	err := c.sendNext()
	if err != nil {
		c.log.Warningf("Failed to send queued message: %v", err)
		err = c.sendDropDecoy()
		if err != nil {
			c.log.Warningf("Failed to send drop decoy traffic: %v", err)
		}
	}
}

func (c *Client) lambdaDTask() {
	err := c.sendDropDecoy()
	if err != nil {
		c.log.Warningf("Failed to send drop decoy traffic: %v", err)
	}
}

func (c *Client) lambdaLTask() {
	err := c.sendLoopDecoy()
	if err != nil {
		c.log.Warningf("Failed to send drop decoy traffic: %v", err)
	}
}

func (c *Client) isDocValid(doc *pki.Document) error {
	const serviceLoop = "loop"
	for _, provider := range doc.Providers {
		_, ok := provider.Kaetzchen[serviceLoop]
		if !ok {
			return errors.New("Error, found a Provider which does not have the loop service.")
		}
	}
	return nil
}
