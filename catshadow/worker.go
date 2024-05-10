// SPDX-FileCopyrightText: 2019, David Stainton <dawuud@riseup.net>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// worker.go - client operations worker
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
	"time"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client"
)

// ReadInboxLambdaPDivisor is used to divide our LambdaP parameter
// to determine our new lambda parameter for our poisson process
// which is used in selecting time intervals between attempting
// to retreive messages from our remote Provider.
const ReadInboxLambdaPDivisor = 8

func getReadInboxInterval(lambdaP float64, lambdaPMaxDelay uint64) time.Duration {
	readInboxMsec := uint64(rand.Exp(rand.NewMath(), (lambdaP / ReadInboxLambdaPDivisor)))
	if readInboxMsec > (lambdaPMaxDelay * ReadInboxLambdaPDivisor) {
		readInboxMsec = lambdaPMaxDelay * ReadInboxLambdaPDivisor
	}
	return time.Duration(readInboxMsec) * time.Millisecond
}

func (c *Client) worker() {
	const maxDuration = time.Duration(math.MaxInt64)

	readInboxTimer := time.NewTimer(maxDuration)
	defer readInboxTimer.Stop()
	c.getReadInboxInterval = func() time.Duration { return maxDuration } // replaced in onDocument

	gcMessagestimer := time.NewTimer(GarbageCollectionInterval)
	defer gcMessagestimer.Stop()

	isConnected := false
	for {
		var qo interface{}
		select {
		case <-c.HaltCh():
			c.log.Debug("Terminating gracefully.")
			c.haltKeyExchanges()
			c.save()
			return
		case <-gcMessagestimer.C:
			c.garbageCollectConversations()
			gcMessagestimer.Reset(GarbageCollectionInterval)
		case <-readInboxTimer.C:
			if isConnected {
				c.log.Debug("READING INBOX")
				c.sendReadInbox()
				readInboxInterval := c.getReadInboxInterval()
				c.log.Debug("<-readInboxTimer.C: Setting readInboxTimer to %s", readInboxInterval)
				readInboxTimer.Reset(readInboxInterval)
			}
		case qo = <-c.opCh:
			switch op := qo.(type) {
			case *opOnline:
				// this operation is run in another goroutine, and is thread safe
				go func() { op.responseChan <- c.goOnline(op.context) }()
			case *opOffline:
				op.responseChan <- c.goOffline()
				isConnected = false
				c.haltKeyExchanges()
			case *opCreateSpool:
				c.doCreateRemoteSpool(op.provider, op.responseChan)
			case *opUpdateSpool:
				if op.descriptor != nil {
					c.spoolReadDescriptor = op.descriptor
					c.save()
					op.responseChan <- nil
					c.restartKeyExchanges()
				} else {
					op.responseChan <- errors.New("Nil spool descriptor")
				}
			case *opAddContact:
				err := c.createContact(op.name, op.sharedSecret)
				if err != nil {
					c.log.Errorf("create contact failure: %s", err.Error())
				}
			case *opRemoveContact:
				op.responseChan <- c.doContactRemoval(op.name)
			case *opRenameContact:
				op.responseChan <- c.doContactRename(op.oldname, op.newname)
			case *opGetExpiration:
				c.doGetExpiration(op.name, op.responseChan)
			case *opChangeExpiration:
				op.responseChan <- c.doChangeExpiration(op.name, op.expiration)
			case *opRestartSending:
				c.sendMessage(op.contact)
			case *opSendMessage:
				c.doSendMessage(op.id, op.name, op.payload)
			case *opGetContacts:
				op.responseChan <- c.contactNicknames
			case *opGetConversation:
				c.doGetConversation(op.name, op.responseChan)
			case *opWipeConversation:
				op.responseChan <- c.doWipeConversation(op.name)
			case *opGetPKIDocument:
				op.responseChan <- c.doGetPKIDocument()
			case *opGetSpoolProviders:
				op.responseChan <- c.doGetSpoolProviders()
			case *opSpoolWriteDescriptor:
				op.responseChan <- c.getSpoolWriteDescriptor()
			default:
				c.fatalErrCh <- errors.New("BUG, unknown operation type.")

			}
		case update := <-c.pandaChan:
			c.processPANDAUpdate(&update)
			continue
		case update := <-c.reunionChan:
			c.processReunionUpdate(&update)
			continue
		case rawClientEvent := <-c.sessionEvents():
			switch event := rawClientEvent.(type) {
			case *client.MessageIDGarbageCollected:
				c.garbageCollectSendMap(event)
			case *client.ConnectionStatusEvent:
				c.log.Infof("Connection status change: isConnected %v", event.IsConnected)
				if isConnected != event.IsConnected && event.IsConnected {
					readInboxInterval := c.getReadInboxInterval()
					c.log.Debug("ConnectionStatusEvent: Connected: Setting readInboxTimer to %s", readInboxInterval)
					readInboxTimer.Reset(readInboxInterval)
					isConnected = event.IsConnected
					c.restartSending()
					c.restartKeyExchanges()
					c.eventCh <- event
					continue
				}
				isConnected = event.IsConnected
				if !isConnected {
					c.log.Debug("ConnectionStatusEvent: Disconnected: Setting readInboxTimer to %s and halting key exchanges", maxDuration)
					readInboxTimer.Reset(maxDuration)
					c.haltKeyExchanges()
				}
				c.eventCh <- event
			case *client.MessageSentEvent:
				c.handleSent(event)
				continue
			case *client.MessageReplyEvent:
				c.handleReply(event)
				continue
			case *client.NewDocumentEvent:
				doc := event.Document
				c.getReadInboxInterval = func() time.Duration { return getReadInboxInterval(doc.LambdaP, doc.LambdaPMaxDelay) }
				readInboxInterval := c.getReadInboxInterval()
				c.log.Debug("NewDocumentEvent: Setting readInboxTimer to %s", readInboxInterval)
				readInboxTimer.Reset(readInboxInterval)
				continue
			default:
				c.fatalErrCh <- fmt.Errorf("bug, received unknown event from client EventSink: %v", event)
				return
			}
		}
	} // end of for loop
}
