// client.go - client
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
	"bytes"
	"errors"
	"fmt"

	"github.com/katzenpost/channels"
	"github.com/katzenpost/client"
	"github.com/katzenpost/client/session"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
	memspoolclient "github.com/katzenpost/memspool/client"
	"github.com/katzenpost/memspool/common"
	pclient "github.com/katzenpost/panda/client"
	panda "github.com/katzenpost/panda/crypto"
	"gopkg.in/op/go-logging.v1"
)

type AddContact struct {
	Name         string
	SharedSecret []byte
}

type SendMessage struct {
	Name    string
	Payload []byte
}

type message struct {
	nickname string
	payload  []byte
	error    error
}

type messageRead struct {
	ch chan message
}

type Client struct {
	worker.Worker

	pandaChan         chan panda.PandaUpdate
	addContactChan    chan AddContact
	sendMessageChan   chan SendMessage
	removeContactChan chan string
	readInboxChan     chan messageRead

	contacts         map[uint64]*Contact
	contactNicknames map[string]*Contact
	spoolReaderChan  *channels.UnreliableSpoolReaderChannel

	client       *client.Client
	session      *session.Session
	spoolService memspoolclient.SpoolService

	log        *logging.Logger
	logBackend *log.Backend
}

func New(logBackend *log.Backend, log *logging.Logger, session *session.Session) *Client {
	spoolService := memspoolclient.New(session)
	client := &Client{
		spoolService:      spoolService,
		session:           session,
		contacts:          make(map[uint64]*Contact),
		contactNicknames:  make(map[string]*Contact),
		log:               log,
		logBackend:        logBackend,
		pandaChan:         make(chan panda.PandaUpdate),
		addContactChan:    make(chan AddContact),
		sendMessageChan:   make(chan SendMessage),
		removeContactChan: make(chan string),
		readInboxChan:     make(chan messageRead),
	}
	return client
}

func (c *Client) Start() error {
	desc, err := c.session.GetService(common.SpoolServiceName)
	if err != nil {
		return err
	}
	if c.spoolReaderChan == nil {
		spoolService := memspoolclient.New(c.session)
		c.spoolReaderChan, err = channels.NewUnreliableSpoolReaderChannel(desc.Name, desc.Provider, spoolService)
		if err != nil {
			return err
		}
	}
	c.Go(c.worker)
	return nil
}

func (c *Client) NewContact(nickname string, sharedSecret []byte) {
	c.addContactChan <- AddContact{
		Name:         nickname,
		SharedSecret: sharedSecret,
	}
}

func (c *Client) createContact(nickname string, sharedSecret []byte) error {
	if _, ok := c.contactNicknames[nickname]; ok {
		return fmt.Errorf("Contact with nickname %s, already exists.", nickname)
	}
	contact, err := NewContact(nickname, c.randId(), c.spoolReaderChan, c.session)
	if err != nil {
		return err
	}
	c.contacts[contact.ID()] = contact
	c.contactNicknames[contact.nickname] = contact
	pandaCfg := c.session.GetPandaConfig()
	if pandaCfg == nil {
		return errors.New("panda failed, must have a panda service configured")
	}
	logPandaClient := c.logBackend.GetLogger(fmt.Sprintf("PANDA_meetingplace_%s", nickname))
	meetingPlace := pclient.New(pandaCfg.BlobSize, c.session, logPandaClient, pandaCfg.Receiver, pandaCfg.Provider)
	if err != nil {
		return err
	}
	kxLog := c.logBackend.GetLogger(fmt.Sprintf("PANDA_keyexchange_%s", nickname))
	kx, err := panda.NewKeyExchange(rand.Reader, kxLog, meetingPlace, sharedSecret, contact.keyExchange, contact.id, c.pandaChan, contact.pandaShutdownChan)
	if err != nil {
		return err
	}
	contact.pandaKeyExchange = kx.Marshal()
	contact.keyExchange = nil
	go kx.Run()
	c.save()

	c.log.Info("New PANDA key exchange in progress.")
	return nil
}

func (c *Client) RemoveContact(nickname string) {
	c.removeContactChan <- nickname
}

func (c *Client) doContactRemoval(nickname string) {
	contact, ok := c.contactNicknames[nickname]
	if !ok {
		c.log.Errorf("contact removal failed, %s not found in contacts", nickname)
		return
	}
	delete(c.contactNicknames, nickname)
	delete(c.contacts, contact.id)
}

func (c *Client) Session() *session.Session {
	return c.session
}

func (c *Client) save() {
	c.log.Debug("Saving statefile.")
	// XXX todo: save state to disk, encrypted with a passphrase
	// using user passphrase --> argon2, nacl secretbox, obviously.
}

func (c *Client) haltKeyExchanges() {
	for _, contact := range c.contacts {
		c.log.Debugf("Halting pending key exchange for '%s' contact.", contact.nickname)
		if contact.isPending {
			close(contact.pandaShutdownChan)
		}
	}
}

func (c *Client) Shutdown() {
	c.Halt()
	c.session.Halt()
}

func (c *Client) processPANDAUpdate(update *panda.PandaUpdate) {
	c.log.Debugf("got panda update: %v", update)
	contact, ok := c.contacts[update.ID]
	if !ok {
		c.log.Error("failure to perform PANDA update: invalid contact ID")
		return
	}

	switch {
	case update.Err != nil:
		contact.pandaResult = update.Err.Error()
		contact.pandaKeyExchange = nil
		contact.pandaShutdownChan = nil
		c.log.Infof("Key exchange with %s failed: %s", contact.nickname, update.Err)
	case update.Serialised != nil:
		if bytes.Equal(contact.pandaKeyExchange, update.Serialised) {
			c.log.Infof("Strange, our PANDA key exchange echoed our exchange bytes: %s", contact.nickname)
			return
		}
		contact.pandaKeyExchange = update.Serialised
	case update.Result != nil:
		c.log.Debug("PANDA exchange completed")
		contact.pandaKeyExchange = nil

		// XXX
		exchange, err := ParseContactExchangeBytes(update.Result)
		if err != nil {
			err = fmt.Errorf("failure to parse contact exchange bytes: %s", err)
			c.log.Error(err.Error())
			contact.pandaResult = err.Error()
		}
		contact.spoolWriterChan = exchange.SpoolWriter
		err = contact.ratchet.ProcessKeyExchange(exchange.SignedKeyExchange)
		if err != nil {
			err = fmt.Errorf("Double ratchet key exchange failure: %s", err)
			c.log.Error(err.Error())
			contact.pandaResult = err.Error()
		}
		contact.isPending = false
		c.log.Debug("Double ratchet key exchange completed!")
	}
	c.save()
}

func (c *Client) SendMessage(nickname string, message []byte) {
	c.sendMessageChan <- SendMessage{
		Name:    nickname,
		Payload: message,
	}
}

func (c *Client) doSendMessage(nickname string, message []byte) {
	contact, ok := c.contactNicknames[nickname]
	if !ok {
		c.log.Errorf("contact %s not found", nickname)
		return
	}
	if contact.isPending {
		c.log.Errorf("cannot send message, contact %s is pending a key exchange", nickname)
		return
	}

	ciphertext := contact.ratchet.Encrypt(nil, message)
	err := contact.spoolWriterChan.Write(c.spoolService, ciphertext)
	if err != nil {
		c.log.Errorf("double ratchet channel write failure: %s", err)
	}
	c.log.Info("Sent message to %s.", nickname)
}

func (c *Client) ReadMessage() (string, []byte, error) {
	ch := make(chan message)
	c.readInboxChan <- messageRead{
		ch: ch,
	}
	message := <-ch
	return message.nickname, message.payload, message.error
}

func (c *Client) doRead(r *messageRead) {
	var err error
	ciphertext, err := c.spoolReaderChan.Read(c.spoolService)
	if err != nil {
		err = fmt.Errorf("failure reading remote spool: %s", err)
		c.log.Debugf(err.Error())
	}
	message := message{}
	for _, contact := range c.contacts {
		plaintext, err := contact.ratchet.Decrypt(ciphertext)
		if err != nil {
			err = fmt.Errorf("failure to decrypt: %s", err)
			c.log.Debugf(err.Error())
			continue
		} else {
			message.nickname = contact.nickname
			message.payload = plaintext
			break
		}
	}
	message.error = err
	r.ch <- message
}

// worker goroutine takes ownership of our contacts
func (c *Client) worker() {
	for {
		select {
		case <-c.HaltCh():
			c.log.Debug("Terminating gracefully.")
			c.haltKeyExchanges()
			return
		case addContact := <-c.addContactChan:
			err := c.createContact(addContact.Name, addContact.SharedSecret)
			if err != nil {
				c.log.Errorf("create contact failure: %s", err.Error())
			}
		case update := <-c.pandaChan:
			c.processPANDAUpdate(&update)
			continue
		case sendMessage := <-c.sendMessageChan:
			c.doSendMessage(sendMessage.Name, sendMessage.Payload)
		case nickname := <-c.removeContactChan:
			c.doContactRemoval(nickname)
		case messageRead := <-c.readInboxChan:
			c.doRead(&messageRead)
		}
	}
}
