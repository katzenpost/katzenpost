// worker.go - client operations worker
// Copyright (C) 2019  David Stainton.
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

package catshadow

import (
	"fmt"

	"github.com/katzenpost/catshadow/constants"
	"github.com/katzenpost/client"
)

func (c *Client) worker() {
	const maxDuration = math.MaxInt64
	mRng := rand.NewMath()

	// Retreive cached PKI doc.
	doc := c.session.CurrentDocument()
	if doc == nil {
		s.fatalErrCh <- errors.New("aborting, PKI doc is nil")
		return
	}

	lambdaP := doc.LambdaP
	lambdaPMsec := uint64(rand.Exp(mRng, lambdaP))
	if lambdaPMsec > doc.LambdaPMaxDelay {
		lambdaPMsec = doc.LambdaPMaxDelay
	}
	lambdaPInterval := time.Duration(lambdaPMsec) * time.Millisecond
	lambdaPTimer := time.NewTimer(lambdaPInterval)
	defer lambdaPTimer.Stop()

	isConnected := true
	for {
		var qo workerOp
		select {
		case <-c.HaltCh():
			c.log.Debug("Terminating gracefully.")
			c.haltKeyExchanges()
			return
		case update := <-c.pandaChan:
			c.processPANDAUpdate(&update)
			continue
		case qo = <-c.opCh:
		case rawClientEvent := <-c.session.EventSink:
			switch event := rawClientEvent.(type) {
			case *client.ConnectionStatusEvent:
				isConnected = event.IsConnected
				c.log.Infof("Connection status change: isConnected %v", isConnected)
			case *client.MessageSentEvent:
				// XXX todo fix me
				continue
			case *client.MessageReplyEvent:
				// XXX todo fix me
				continue
			case *client.NewDocumentEvent:
				doc = event.Document
				lambdaP = doc.LambdaP
				// XXX todo fix me
				continue
			default:
				err := fmt.Errorf("bug, received unknown event from client EventSink: %v", event)
				c.log.Error(err.Error())
				c.fatalErrCh <- err
				return
			}
		}

		if qo != nil {
			switch op := qo.(type) {
			case *opAddContact:
				err := c.createContact(op.name, op.sharedSecret)
				if err != nil {
					c.log.Errorf("create contact failure: %s", err.Error())
				}
			case *opRemoveContact:
				c.doContactRemoval(op.name)
			case *opSendMessage:
				c.doSendMessage(op.name, op.payload)
			case *opGetNicknames:
				names := []string{}
				for contact := range c.contactNicknames {
					names = append(names, contact)
				}
				op.responseChan <- names
			}
			continue
		} // end of if qo != nil {

	} // end of for loop
}
