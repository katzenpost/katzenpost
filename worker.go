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
	"errors"
	"fmt"
	"math"
	mrand "math/rand"
	"time"

	"github.com/katzenpost/catshadow/constants"
	"github.com/katzenpost/client"
	"github.com/katzenpost/core/crypto/rand"
)

func getReadInboxInterval(mRng *mrand.Rand, lambdaP float64, lambdaPMaxDelay uint64) time.Duration {
	readInboxMsec := uint64(rand.Exp(rand.NewMath(), (lambdaP / constants.ReadInboxLambdaPDivisor)))
	if readInboxMsec > (lambdaPMaxDelay * constants.ReadInboxLambdaPDivisor) {
		readInboxMsec = lambdaPMaxDelay * constants.ReadInboxLambdaPDivisor
	}
	return time.Duration(readInboxMsec) * time.Millisecond
}

func (c *Client) worker() {
	const maxDuration = time.Duration(math.MaxInt64)
	mRng := rand.NewMath()

	// Retreive cached PKI doc.
	doc := c.session.CurrentDocument()
	if doc == nil {
		c.fatalErrCh <- errors.New("aborting, PKI doc is nil")
		return
	}

	readInboxInterval := getReadInboxInterval(mRng, doc.LambdaP, doc.LambdaPMaxDelay)
	readInboxTimer := time.NewTimer(readInboxInterval)
	defer readInboxTimer.Stop()

	gcMessagestimer := time.NewTimer(constants.GarbageCollectionInterval)

	isConnected := true
	for {
		var qo workerOp
		select {
		case <-c.HaltCh():
			c.log.Debug("Terminating gracefully.")
			c.haltKeyExchanges()
			return
		case <-gcMessagestimer.C:
			c.garbageCollectConversations()
			gcMessagestimer.Reset(constants.GarbageCollectionInterval)
		case <-readInboxTimer.C:
			if isConnected {
				c.log.Debug("READING INBOX")
				c.sendReadInbox()
				readInboxInterval := getReadInboxInterval(mRng, doc.LambdaP, doc.LambdaPMaxDelay)
				readInboxTimer.Reset(readInboxInterval)
			}
		case qo = <-c.opCh:
			switch op := qo.(type) {
			case *opAddContact:
				err := c.createContact(op.name, op.sharedSecret)
				if err != nil {
					c.log.Errorf("create contact failure: %s", err.Error())
				}
			case *opRemoveContact:
				c.doContactRemoval(op.name)
			case *opSendMessage:
				c.doSendMessage(op.id, op.name, op.payload)
			case *opGetNicknames:
				names := []string{}
				for contact := range c.contactNicknames {
					names = append(names, contact)
				}
				op.responseChan <- names
			default:
				c.fatalErrCh <- errors.New("BUG, unknown operation type.")
			}
		case update := <-c.pandaChan:
			c.processPANDAUpdate(&update)
			continue
		case rawClientEvent := <-c.session.EventSink:
			switch event := rawClientEvent.(type) {
			case *client.MessageIDGarbageCollected:
				c.garbageCollectSendMap(event)
			case *client.ConnectionStatusEvent:
				c.log.Infof("Connection status change: isConnected %v", event.IsConnected)
				if isConnected != event.IsConnected && event.IsConnected {
					readInboxInterval := getReadInboxInterval(mRng, doc.LambdaP, doc.LambdaPMaxDelay)
					readInboxTimer.Reset(readInboxInterval)
					isConnected = event.IsConnected
					c.eventCh.In() <- event
					continue
				}
				isConnected = event.IsConnected
				if !isConnected {
					readInboxTimer.Reset(maxDuration)
				}
				c.eventCh.In() <- event
			case *client.MessageSentEvent:
				c.handleSent(event)
				continue
			case *client.MessageReplyEvent:
				c.handleReply(event)
				continue
			case *client.NewDocumentEvent:
				doc = event.Document
				readInboxInterval := getReadInboxInterval(mRng, doc.LambdaP, doc.LambdaPMaxDelay)
				readInboxTimer.Reset(readInboxInterval)
				continue
			default:
				c.fatalErrCh <- fmt.Errorf("bug, received unknown event from client EventSink: %v", event)
				return
			}
		}
	} // end of for loop
}
