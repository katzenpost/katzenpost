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

	"github.com/katzenpost/client"
)

func (c *Client) worker() {
	var isConnected bool
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
		} // end of if qo != nil {

	} // end of for loop
}
