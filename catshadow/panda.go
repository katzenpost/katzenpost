// SPDX-FileCopyrightText: 2019, David Stainton <dawuud@riseup.net>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// panda.go - catshadow
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
	"bytes"
	"errors"
	"fmt"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client"
	pclient "github.com/katzenpost/katzenpost/panda/client"
	pCommon "github.com/katzenpost/katzenpost/panda/common"
	panda "github.com/katzenpost/katzenpost/panda/crypto"
)

func (c *Client) doPANDAExchange(contact *Contact) error {
	// Use PANDA
	p, err := c.session.GetService(pCommon.PandaCapability)
	if err != nil {
		c.log.Errorf("Failed to get %s: %s", pCommon.PandaCapability, err)
		return err
	}

	logPandaClient := c.logBackend.GetLogger(fmt.Sprintf("PANDA_meetingplace_%s", contact.Nickname))
	meetingPlace := pclient.New(pandaBlobSize, c.session, logPandaClient, p.Name, p.Provider)
	// get the current document and shared random
	doc := c.session.CurrentDocument()
	sharedRandom := doc.PriorSharedRandom[0]
	kxLog := c.logBackend.GetLogger(fmt.Sprintf("PANDA_keyexchange_%s", contact.Nickname))

	var kx *panda.KeyExchange
	if contact.pandaKeyExchange != nil {
		kx, err = panda.UnmarshalKeyExchange(rand.Reader, kxLog, meetingPlace, contact.pandaKeyExchange, contact.ID(), c.pandaChan, contact.pandaShutdownChan)
		if err != nil {
			return err
		}
		kx.SetSharedRandom(sharedRandom)
	} else {
		if c.spoolReadDescriptor == nil {
			return ErrNoSpool
		}

		kx, err = panda.NewKeyExchange(rand.Reader, kxLog, meetingPlace, sharedRandom, contact.sharedSecret, contact.keyExchange, contact.id, c.pandaChan, contact.pandaShutdownChan)
		if err != nil {
			return err
		}
	}
	contact.pandaKeyExchange = kx.Marshal()
	contact.keyExchange = nil
	c.Go(kx.Run)
	c.save()

	c.log.Info("New PANDA key exchange in progress.")
	return nil
}

func (c *Client) processPANDAUpdate(update *panda.PandaUpdate) {
	contact, ok := c.contacts[update.ID]
	if !ok {
		c.log.Error("failure to perform PANDA update: invalid contact ID")
		return
	}

	switch {
	case update.Err != nil:
		// restart the handshake with the current state if the error is due to SURB-ACK timeout
		if update.Err == client.ErrReplyTimeout {
			c.log.Error("PANDA handshake for client %s timed-out; restarting exchange", contact.Nickname)
			logPandaMeeting := c.logBackend.GetLogger(fmt.Sprintf("PANDA_meetingplace_%s", contact.Nickname))
			p, err := c.session.GetService(pCommon.PandaCapability)
			if err != nil {
				c.log.Errorf("Failed to get %s: %s", pCommon.PandaCapability, err)
			}

			meetingPlace := pclient.New(pandaBlobSize, c.session, logPandaMeeting, p.Name, p.Provider)
			logPandaKx := c.logBackend.GetLogger(fmt.Sprintf("PANDA_keyexchange_%s", contact.Nickname))
			kx, err := panda.UnmarshalKeyExchange(rand.Reader, logPandaKx, meetingPlace, contact.pandaKeyExchange, contact.ID(), c.pandaChan, contact.pandaShutdownChan)
			if err != nil {
				c.log.Errorf("Failed to UnmarshalKeyExchange for %s: %s", contact.Nickname, err)
				return
			}
			c.Go(kx.Run)
		}
		contact.pandaResult = update.Err.Error()
		contact.pandaShutdownChan = nil
		c.log.Infof("Key exchange with %s failed: %s", contact.Nickname, update.Err)
		c.eventCh <- &KeyExchangeCompletedEvent{
			Nickname: contact.Nickname,
			Err:      update.Err,
		}
	case update.Serialised != nil:
		if bytes.Equal(contact.pandaKeyExchange, update.Serialised) {
			c.log.Infof("Strange, our PANDA key exchange echoed our exchange bytes: %s", contact.Nickname)
			c.eventCh <- &KeyExchangeCompletedEvent{
				Nickname: contact.Nickname,
				Err:      errors.New("strange, our PANDA key exchange echoed our exchange bytes"),
			}
			return
		}
		contact.pandaKeyExchange = update.Serialised
	case update.Result != nil:
		c.log.Debug("PANDA exchange completed")
		contact.pandaKeyExchange = nil
		exchange, err := parseContactExchangeBytes(update.Result)
		if err != nil {
			err = fmt.Errorf("failure to parse contact exchange bytes: %s", err)
			c.log.Error(err.Error())
			contact.pandaResult = err.Error()
			contact.IsPending = false
			c.save()
			c.eventCh <- &KeyExchangeCompletedEvent{
				Nickname: contact.Nickname,
				Err:      err,
			}
			return
		}
		contact.ratchetMutex.Lock()
		err = contact.ratchet.ProcessKeyExchange(exchange.KeyExchange)
		contact.ratchetMutex.Unlock()
		if err != nil {
			err = fmt.Errorf("Double ratchet key exchange failure: %s", err)
			c.log.Error(err.Error())
			contact.pandaResult = err.Error()
			contact.IsPending = false
			c.save()
			c.eventCh <- &KeyExchangeCompletedEvent{
				Nickname: contact.Nickname,
				Err:      err,
			}
			return
		}
		contact.spoolWriteDescriptor = exchange.SpoolWriteDescriptor
		contact.IsPending = false
		c.log.Info("Double ratchet key exchange completed!")
		contact.sharedSecret = nil
		c.eventCh <- &KeyExchangeCompletedEvent{
			Nickname: contact.Nickname,
		}
	}
	c.save()
}
