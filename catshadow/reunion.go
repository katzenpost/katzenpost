// SPDX-FileCopyrightText: 2019, David Stainton <dawuud@riseup.net>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// reunion.go - reunion
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

	rClient "github.com/katzenpost/katzenpost/reunion/client"
	rTrans "github.com/katzenpost/katzenpost/reunion/transports/katzenpost"
)

func (c *Client) processReunionUpdate(update *rClient.ReunionUpdate) {
	c.log.Debug("got a reunion update for exchange %v", update.ExchangeID)
	contact, ok := c.contacts[update.ContactID]
	if !ok {
		c.log.Error("failure to perform Reunion update: invalid contact ID")
		return
	}
	if !contact.IsPending {
		// we performed multiple exchanges, but this one has probably arrived too late
		c.log.Debugf("received reunion update for exchange %v after pairing occurred", update.ExchangeID)
		// remove the map entries
		if _, ok := contact.reunionKeyExchange[update.ExchangeID]; ok {
			delete(contact.reunionKeyExchange, update.ExchangeID)
		}
		if _, ok := contact.reunionResult[update.ExchangeID]; ok {
			delete(contact.reunionResult, update.ExchangeID)
		}
		return
	}
	switch {
	case update.Error != nil:
		contact.reunionResult[update.ExchangeID] = update.Error.Error()
		c.log.Infof("Reunion key exchange %v with %s failed: %s", update.ExchangeID, contact.Nickname, update.Error)
		if _, ok := contact.reunionKeyExchange[update.ExchangeID]; ok {
			delete(contact.reunionKeyExchange, update.ExchangeID) // remove map entry
		}
		// XXX: if there are other reunion key exchanges pending for this client, we probably do not want to emit an error event just yet...
		if len(contact.reunionKeyExchange) == 0 {
			c.eventCh <- &KeyExchangeCompletedEvent{
				Nickname: contact.Nickname,
				Err:      update.Error,
			}
		}
		return

	case update.Serialized != nil:
		if ex, ok := contact.reunionKeyExchange[update.ExchangeID]; ok {
			ex.serialized = update.Serialized
			c.log.Infof("Reunion key exchange %v with %s update received", update.ExchangeID, contact.Nickname)
		} else {
			c.log.Infof("Reunion key exchange %v with %s update received after another valid exchange", update.ExchangeID, contact.Nickname)
		}
	case update.Result != nil:
		c.log.Debugf("Reunion exchange %v completed", update.ExchangeID)
		exchange, err := parseContactExchangeBytes(update.Result)
		if _, ok := contact.reunionKeyExchange[update.ExchangeID]; ok {
			delete(contact.reunionKeyExchange, update.ExchangeID) // remove map entry
		}
		if err != nil {
			err = fmt.Errorf("Reunion failure to parse contact exchange %v bytes: %s", update.ExchangeID, err)
			c.log.Error(err.Error())
			contact.reunionResult[update.ExchangeID] = err.Error()
			c.save()
			c.eventCh <- &KeyExchangeCompletedEvent{
				Nickname: contact.Nickname,
				Err:      err,
			}
			return
		}
		contact.spoolWriteDescriptor = exchange.SpoolWriteDescriptor
		contact.ratchetMutex.Lock()
		err = contact.ratchet.ProcessKeyExchange(exchange.KeyExchange)
		contact.ratchetMutex.Unlock()
		if err != nil {
			err = fmt.Errorf("Reunion double ratchet key exchange %v failure: %s", update.ExchangeID, err)
			c.log.Error(err.Error())
			contact.reunionResult[update.ExchangeID] = err.Error()
			c.save()
			c.eventCh <- &KeyExchangeCompletedEvent{
				Nickname: contact.Nickname,
				Err:      err,
			}
			return
		}
		// XXX: should purge the reunionResults now...
		contact.keyExchange = nil
		contact.IsPending = false
		c.log.Info("Reunion double ratchet key exchange completed by exchange %v!", update.ExchangeID)
		c.eventCh <- &KeyExchangeCompletedEvent{
			Nickname: contact.Nickname,
		}
	}
	c.save()
}

// restart reunion exchanges
func (c *Client) restartReunionExchanges() {
	transports, err := c.getReunionTransports()
	if err != nil {
		c.log.Warningf("Reunion configured, but no transports found")
		return
	}
	for _, contact := range c.contacts {
		if contact.IsPending {
			err := c.initKeyExchange(contact)
			if err != ErrAlreadyHaveKeyExchange && err != nil {
				// skip if a ratchet keyexchange cannot be found or created
				c.log.Errorf("Failed to resume key exchange for %s: %s", contact.Nickname, err)
				continue
			}
			for eid, ex := range contact.reunionKeyExchange {
				// see if the transport still exists in current transports
				m := false
				for _, tr := range transports {
					if tr.Recipient == ex.recipient && tr.Provider == ex.provider {
						m = true
						lstr := fmt.Sprintf("reunion with %s at %s@%s", contact.Nickname, tr.Recipient, tr.Provider)
						dblog := c.logBackend.GetLogger(lstr)
						exchange, err := rClient.NewExchangeFromSnapshot(ex.serialized, dblog, tr, c.reunionChan, contact.reunionShutdownChan)
						if err != nil {
							c.log.Warningf("Reunion failed: %v", err)
						} else {
							c.Go(exchange.Run)
							break
						}
					}
				}
				// transport not found
				if m == false {
					c.log.Warningf("Reunion transport %s@%s no longer exists!", ex.recipient, ex.provider)
					delete(contact.reunionKeyExchange, eid)
				}
			}
		}
	}
}

func (c *Client) getReunionTransports() ([]*rTrans.Transport, error) {
	// Get consensus
	doc := c.session.CurrentDocument()
	if doc == nil {
		return nil, errors.New("No current document, wtf")
	}
	transports := make([]*rTrans.Transport, 0)

	// Get reunion endpoints and epoch values
	for _, p := range doc.Providers {
		if r, ok := p.Kaetzchen["reunion"]; ok {
			if ep, ok := r["endpoint"]; ok {
				ep := ep.(string)
				trans := &rTrans.Transport{Session: c.session, Recipient: ep, Provider: p.Name}
				c.log.Debugf("Adding transport %v", trans)
				transports = append(transports, trans)
			} else {
				return nil, errors.New("Provider kaetzchen descriptor missing endpoint")
			}
		}
	}
	if len(transports) > 0 {
		return transports, nil
	}
	return nil, errors.New("Found no reunion transports")
}

func (c *Client) doReunion(contact *Contact) error {
	c.log.Info("DoReunion called")
	rtransports, err := c.getReunionTransports()
	if err != nil {
		return err
	}
	for _, tr := range rtransports {
		epochs, err := tr.CurrentEpochs()
		if err != nil {
			return err
		}
		srvs, err := tr.CurrentSharedRandoms()
		if err != nil {
			return err
		}
		// what should we do to reduce the number of exchanges initiated?
		// if this is the first reunion, choose the latest published epoch and srv ?
		// (after some time, try other epochs and srvs?)
		for _, srv := range srvs[0:1] {
			for _, epoch := range epochs {
				lstr := fmt.Sprintf("reunion with %s at %s@%s:%d", contact.Nickname, tr.Recipient, tr.Provider, epoch)
				dblog := c.logBackend.GetLogger(lstr)
				ex, err := rClient.NewExchange(contact.keyExchange, dblog, tr, contact.ID(), contact.sharedSecret, srv, epoch, c.reunionChan, contact.reunionShutdownChan)
				if err != nil {
					return err
				}
				// create a mapping from exchange ID to transport and serialized updates
				contact.reunionKeyExchange[ex.ExchangeID] = boundExchange{recipient: tr.Recipient, provider: tr.Provider}
				go ex.Run()
				c.log.Info("New reunion exchange %v in progress.", ex.ExchangeID)
			}
		}
	}
	return nil
}
