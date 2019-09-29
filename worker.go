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

import ()

func (c *Client) worker() {
	c.readInboxPoissonTimer.Start()
	defer c.readInboxPoissonTimer.Stop()

	for {
		var qo workerOp
		select {
		case <-c.HaltCh():
			c.log.Debug("Terminating gracefully.")
			c.haltKeyExchanges()
			return
		case <-c.readInboxPoissonTimer.Channel():
			//c.readInbox()
			//c.readInboxPoissonTimer.Next() // XXX todo: MUST set timer to max val when disconnected. duh.
		case update := <-c.pandaChan:
			c.log.Info("BEFORE PANDA UPDATE")
			c.processPANDAUpdate(&update)
			c.log.Info("AFTER PANDA UPDATE")
		case qo = <-c.opCh:
		}

		switch op := qo.(type) {
		case *opAddContact:
			c.log.Info("BEFORE CREATE CONTACT")
			err := c.createContact(op.name, op.sharedSecret)
			if err != nil {
				c.log.Errorf("create contact failure: %s", err.Error())
			}
			c.log.Info("AFTER CREATE CONTACT")
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
	} // end of for loop
}
