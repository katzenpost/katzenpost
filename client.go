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
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/katzenpost/channels"
	"github.com/katzenpost/client"
	"github.com/katzenpost/client/poisson"
	"github.com/katzenpost/client/session"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
	memspoolclient "github.com/katzenpost/memspool/client"
	"github.com/katzenpost/memspool/common"
	pclient "github.com/katzenpost/panda/client"
	panda "github.com/katzenpost/panda/crypto"
	"github.com/ugorji/go/codec"
	"gopkg.in/op/go-logging.v1"
)

const (
	// these two constants control the frequency of polling the remote
	// inbox for new messages
	readInboxPoissonLambda = 0.0001234
	readInboxPoissonMax    = 90000
)

type addContact struct {
	Name         string
	SharedSecret []byte
}

type sendMessage struct {
	Name    string
	Payload []byte
}

// Client is the mixnet client which interacts with other clients
// and services on the network.
type Client struct {
	worker.Worker

	pandaChan         chan panda.PandaUpdate
	addContactChan    chan addContact
	getNicknamesChan  chan chan []string
	sendMessageChan   chan sendMessage
	removeContactChan chan string

	stateWorker           *StateWriter
	linkKey               *ecdh.PrivateKey
	user                  string
	contacts              map[uint64]*Contact
	contactNicknames      map[string]*Contact
	spoolReaderChan       *channels.UnreliableSpoolReaderChannel
	inbox                 []*Message
	inboxMutex            *sync.Mutex
	readInboxPoissonTimer *poisson.Fount

	client       *client.Client
	session      *session.Session
	spoolService memspoolclient.SpoolService

	log        *logging.Logger
	logBackend *log.Backend
}

// NewClientAndRemoteSpool creates a new Client and creates a new remote spool
// for collecting messages destined to this Client. The Client is associated with
// this remote spool and this state is preserved in the encrypted statefile, of course.
// This constructor of Client is used when creating a new Client as opposed to loading
// the previously saved state for an existing Client.
func NewClientAndRemoteSpool(logBackend *log.Backend, mixnetClient *client.Client, stateWorker *StateWriter, user string, linkKey *ecdh.PrivateKey) (*Client, error) {
	state := &State{
		Contacts: make([]*Contact, 0),
		Inbox:    make([]*Message, 0),
		User:     user,
		Provider: mixnetClient.Provider(),
		LinkKey:  linkKey,
	}
	client, err := New(mixnetClient.GetBackendLog(), mixnetClient, stateWorker, state)
	if err != nil {
		return nil, err
	}
	client.save()
	err = client.CreateRemoteSpool()
	if err != nil {
		return nil, err
	}
	client.save()
	return client, nil
}

// New creates a new Client instance given a mixnetClient, stateWorker and state.
// This constructor is used to load the previously saved state of a Client.
func New(logBackend *log.Backend, mixnetClient *client.Client, stateWorker *StateWriter, state *State) (*Client, error) {
	session, err := mixnetClient.NewSession(state.LinkKey)
	if err != nil {
		return nil, err
	}
	c := &Client{
		pandaChan:         make(chan panda.PandaUpdate),
		addContactChan:    make(chan addContact),
		sendMessageChan:   make(chan sendMessage),
		getNicknamesChan:  make(chan chan []string),
		removeContactChan: make(chan string),
		contacts:          make(map[uint64]*Contact),
		contactNicknames:  make(map[string]*Contact),
		spoolReaderChan:   state.SpoolReaderChan,
		linkKey:           state.LinkKey,
		user:              state.User,
		inbox:             state.Inbox,
		inboxMutex:        new(sync.Mutex),
		stateWorker:       stateWorker,
		readInboxPoissonTimer: poisson.NewTimer(&poisson.Descriptor{
			Lambda: readInboxPoissonLambda,
			Max:    readInboxPoissonMax,
		}),
		client:       mixnetClient,
		session:      session,
		spoolService: memspoolclient.New(session),
		log:          logBackend.GetLogger("catshadow"),
		logBackend:   logBackend,
	}
	for _, contact := range state.Contacts {
		c.contacts[contact.id] = contact
		c.contactNicknames[contact.nickname] = contact
	}
	return c, nil
}

// Start starts the client worker goroutine and the
// read-inbox worker goroutine.
func (c *Client) Start() {
	pandaCfg := c.session.GetPandaConfig()
	if pandaCfg == nil {
		panic("panda failed, must have a panda service configured")
	}
	for _, contact := range c.contacts {
		if contact.isPending {
			logPandaMeeting := c.logBackend.GetLogger(fmt.Sprintf("PANDA_meetingplace_%s", contact.nickname))
			meetingPlace := pclient.New(pandaCfg.BlobSize, c.session, logPandaMeeting, pandaCfg.Receiver, pandaCfg.Provider)
			logPandaKx := c.logBackend.GetLogger(fmt.Sprintf("PANDA_keyexchange_%s", contact.nickname))
			kx, err := panda.UnmarshalKeyExchange(rand.Reader, logPandaKx, meetingPlace, contact.pandaKeyExchange)
			if err != nil {
				panic(err)
			}
			go kx.Run()
		}
	}
	c.Go(c.worker)
}

// CreateRemoteSpool creates a remote spool for collecting messages
// destined to this Client.
func (c *Client) CreateRemoteSpool() error {
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
		c.log.Debug("remote reader spool created successfully")
	}
	return nil
}

// NewContact adds a new contact to the Client's state. This starts
// the PANDA protocol instance for this contact where intermediate
// states will be preserved in the encrypted statefile such that
// progress on the PANDA key exchange can be continued at a later
// time after program shutdown or restart.
func (c *Client) NewContact(nickname string, sharedSecret []byte) {
	c.addContactChan <- addContact{
		Name:         nickname,
		SharedSecret: sharedSecret,
	}
}

func (c *Client) randID() uint64 {
	var idBytes [8]byte
	for {
		_, err := rand.Reader.Read(idBytes[:])
		if err != nil {
			panic(err)
		}
		n := binary.LittleEndian.Uint64(idBytes[:])
		if n == 0 {
			continue
		}
		if _, ok := c.contacts[n]; ok {
			continue
		}
		return n
	}
	// unreachable
}

func (c *Client) createContact(nickname string, sharedSecret []byte) error {
	if _, ok := c.contactNicknames[nickname]; ok {
		return fmt.Errorf("Contact with nickname %s, already exists.", nickname)
	}
	contact, err := NewContact(nickname, c.randID(), c.spoolReaderChan, c.session)
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

func (c *Client) GetNicknames() []string {
	responseChan := make(chan []string)
	c.getNicknamesChan <- responseChan
	return <-responseChan
}

// RemoveContact removes a contact from the Client's state.
func (c *Client) RemoveContact(nickname string) {
	c.removeContactChan <- nickname
}

func (c *Client) doContactRemoval(nickname string) {
	contact, ok := c.contactNicknames[nickname]
	if !ok {
		c.log.Errorf("contact removal failed, %s not found in contacts", nickname)
		return
	}
	if contact.isPending {
		if contact.pandaShutdownChan != nil {
			close(contact.pandaShutdownChan)
		}
	}
	delete(c.contactNicknames, nickname)
	delete(c.contacts, contact.id)
	c.save()
}

func (c *Client) save() {
	c.log.Debug("Saving statefile.")
	serialized, err := c.marshal()
	if err != nil {
		panic(err)
	}
	err = c.stateWorker.writeState(serialized)
	if err != nil {
		panic(err)
	}
}

func (c *Client) marshal() ([]byte, error) {
	contacts := []*Contact{}
	for _, contact := range c.contacts {
		contacts = append(contacts, contact)
	}
	s := &State{
		SpoolReaderChan: c.spoolReaderChan,
		Contacts:        contacts,
		LinkKey:         c.linkKey,
		User:            c.user,
		Provider:        c.client.Provider(),
		Inbox:           c.GetInbox(),
	}
	var serialized []byte
	err := codec.NewEncoderBytes(&serialized, cborHandle).Encode(s)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

func (c *Client) haltKeyExchanges() {
	for _, contact := range c.contacts {
		c.log.Debugf("Halting pending key exchange for '%s' contact.", contact.nickname)
		if contact.isPending {
			if contact.pandaShutdownChan != nil {
				close(contact.pandaShutdownChan)
			}
		}
	}
}

// Shutdown shuts down the client.
func (c *Client) Shutdown() {
	c.save()
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
		exchange, err := parseContactExchangeBytes(update.Result)
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

// SendMessage sends a message to the Client contact with the given nickname.
func (c *Client) SendMessage(nickname string, message []byte) {
	c.sendMessageChan <- sendMessage{
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

	payload := [channels.DoubleRatchetPayloadLength]byte{}
	binary.BigEndian.PutUint32(payload[:4], uint32(len(message)))
	copy(payload[4:], message)
	ciphertext := contact.ratchet.Encrypt(nil, payload[:])
	c.save()

	err := contact.spoolWriterChan.Write(c.spoolService, ciphertext)
	if err != nil {
		c.log.Errorf("double ratchet channel write failure: %s", err)
	}
	c.log.Info("Sent message to %s.", nickname)
}

// GetInbox returns the Client's inbox.
func (c *Client) GetInbox() []*Message {
	c.inboxMutex.Lock()
	defer c.inboxMutex.Unlock()
	return c.inbox
}

func (c *Client) readInbox() bool {
	var err error
	ciphertext, err := c.spoolReaderChan.Read(c.spoolService)
	if err != nil {
		c.log.Debugf("failure reading remote spool: %s", err)
		return false
	}
	message := Message{}
	var decrypted bool
	for _, contact := range c.contacts {
		plaintext, err := contact.ratchet.Decrypt(ciphertext)
		if err != nil {
			continue
		} else {
			decrypted = true
			message.Nickname = contact.nickname
			payloadLen := binary.BigEndian.Uint32(plaintext[:4])
			message.Plaintext = plaintext[4 : 4+payloadLen]
			message.ReceivedTime = time.Now()
			break
		}
	}
	if decrypted {
		c.inboxMutex.Lock()
		defer c.inboxMutex.Unlock()
		c.inbox = append(c.inbox, &message)
		return true
	}
	c.log.Debugf("failure to find ratchet which will decrypt this message: %s", err)
	return false
}

// worker goroutine takes ownership of our contacts
func (c *Client) worker() {
	c.readInboxPoissonTimer.Start()
	defer c.readInboxPoissonTimer.Stop()
	for {
		select {
		case <-c.HaltCh():
			c.log.Debug("Terminating gracefully.")
			c.haltKeyExchanges()
			return
		case <-c.readInboxPoissonTimer.Channel():
			if c.readInbox() {
				c.save()
			}
			c.readInboxPoissonTimer.Next()
		case addContact := <-c.addContactChan:
			err := c.createContact(addContact.Name, addContact.SharedSecret)
			if err != nil {
				c.log.Errorf("create contact failure: %s", err.Error())
			}
		case responseChan := <-c.getNicknamesChan:
			names := []string{}
			for contact := range c.contactNicknames {
				names = append(names, contact)
			}
			responseChan <- names
		case update := <-c.pandaChan:
			c.processPANDAUpdate(&update)
		case sendMessage := <-c.sendMessageChan:
			c.doSendMessage(sendMessage.Name, sendMessage.Payload)
		case nickname := <-c.removeContactChan:
			c.doContactRemoval(nickname)
		}
	}
}
