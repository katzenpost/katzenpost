// SPDX-FileCopyrightText: 2019, David Stainton <dawuud@riseup.net>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// client.go - client
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

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/client"
	cConstants "github.com/katzenpost/client/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
	memspoolclient "github.com/katzenpost/memspool/client"
	"github.com/katzenpost/memspool/common"
	pclient "github.com/katzenpost/panda/client"
	panda "github.com/katzenpost/panda/crypto"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

// Client is the mixnet client which interacts with other clients
// and services on the network.
type Client struct {
	worker.Worker

	eventCh    channels.Channel
	EventSink  chan interface{}
	opCh       chan interface{}
	pandaChan  chan panda.PandaUpdate
	fatalErrCh chan error

	// messageID -> *SentMessageDescriptor
	sendMap *sync.Map

	stateWorker         *StateWriter
	linkKey             *ecdh.PrivateKey
	user                string
	contacts            map[uint64]*Contact
	contactNicknames    map[string]*Contact
	spoolReadDescriptor *memspoolclient.SpoolReadDescriptor
	conversations       map[string]map[MessageID]*Message
	conversationsMutex  *sync.Mutex

	client  *client.Client
	session *client.Session

	log        *logging.Logger
	logBackend *log.Backend
}

type MessageID [MessageIDLen]byte

// NewClientAndRemoteSpool creates a new Client and creates a new remote spool
// for collecting messages destined to this Client. The Client is associated with
// this remote spool and this state is preserved in the encrypted statefile, of course.
// This constructor of Client is used when creating a new Client as opposed to loading
// the previously saved state for an existing Client.
func NewClientAndRemoteSpool(logBackend *log.Backend, mixnetClient *client.Client, stateWorker *StateWriter, user string, linkKey *ecdh.PrivateKey) (*Client, error) {
	state := &State{
		Contacts:      make([]*Contact, 0),
		Conversations: make(map[string]map[MessageID]*Message),
		User:          user,
		Provider:      mixnetClient.Provider(),
		LinkKey:       linkKey,
	}
	client, err := New(logBackend, mixnetClient, stateWorker, state)
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
		eventCh:             channels.NewInfiniteChannel(),
		EventSink:           make(chan interface{}),
		opCh:                make(chan interface{}, 8),
		pandaChan:           make(chan panda.PandaUpdate),
		fatalErrCh:          make(chan error),
		sendMap:             new(sync.Map),
		contacts:            make(map[uint64]*Contact),
		contactNicknames:    make(map[string]*Contact),
		spoolReadDescriptor: state.SpoolReadDescriptor,
		linkKey:             state.LinkKey,
		user:                state.User,
		conversations:       state.Conversations,
		conversationsMutex:  new(sync.Mutex),
		stateWorker:         stateWorker,
		client:              mixnetClient,
		session:             session,
		log:                 logBackend.GetLogger("catshadow"),
		logBackend:          logBackend,
	}
	for _, contact := range state.Contacts {
		contact.ratchetMutex = new(sync.Mutex)
		c.contacts[contact.id] = contact
		c.contactNicknames[contact.Nickname] = contact
	}
	return c, nil
}

// Start starts the client worker goroutine and the
// read-inbox worker goroutine.
func (c *Client) Start() {
	c.garbageCollectConversations()
	pandaCfg := c.session.GetPandaConfig()
	if pandaCfg == nil {
		panic("panda failed, must have a panda service configured")
	}
	c.Go(c.eventSinkWorker)
	for _, contact := range c.contacts {
		if contact.IsPending {
			logPandaMeeting := c.logBackend.GetLogger(fmt.Sprintf("PANDA_meetingplace_%s", contact.Nickname))
			meetingPlace := pclient.New(pandaCfg.BlobSize, c.session, logPandaMeeting, pandaCfg.Receiver, pandaCfg.Provider)
			logPandaKx := c.logBackend.GetLogger(fmt.Sprintf("PANDA_keyexchange_%s", contact.Nickname))
			kx, err := panda.UnmarshalKeyExchange(rand.Reader, logPandaKx, meetingPlace, contact.pandaKeyExchange)
			if err != nil {
				panic(err)
			}
			go kx.Run()
		}
	}
	c.Go(c.worker)
	// Start the fatal error watcher.
	go func() {
		err, ok := <-c.fatalErrCh
		if !ok {
			return
		}
		c.log.Warningf("Shutting down due to error: %v", err)
		c.Shutdown()
	}()
}

func (c *Client) eventSinkWorker() {
	defer func() {
		c.log.Debug("Event sink worker terminating gracefully.")
		close(c.EventSink)
	}()
	for {
		var event interface{} = nil
		select {
		case <-c.HaltCh():
			return
		case event = <-c.eventCh.Out():
		}
		select {
		case c.EventSink <- event:
		case <-c.HaltCh():
			return
		}
	}
}

func (c *Client) garbageCollectConversations() {
	c.conversationsMutex.Lock()
	defer c.conversationsMutex.Unlock()
	for _, messages := range c.conversations {
		for mesgID, message := range messages {
			if time.Now().After(message.Timestamp.Add(MessageExpirationDuration)) {
				delete(messages, mesgID)
			}
		}
	}
}

// CreateRemoteSpool creates a remote spool for collecting messages
// destined to this Client. This method blocks until the reply from
// the remote spool service is received or the round trip timeout is reached.
func (c *Client) CreateRemoteSpool() error {
	desc, err := c.session.GetService(common.SpoolServiceName)
	if err != nil {
		return err
	}
	if c.spoolReadDescriptor == nil {
		// Be warned that the call to NewSpoolReadDescriptor blocks until the reply
		// is received or the round trip timeout is reached.
		c.spoolReadDescriptor, err = memspoolclient.NewSpoolReadDescriptor(desc.Name, desc.Provider, c.session)
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
	c.opCh <- &opAddContact{
		name:         nickname,
		sharedSecret: sharedSecret,
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
	contact, err := NewContact(nickname, c.randID(), c.spoolReadDescriptor, c.session)
	if err != nil {
		return err
	}
	c.contacts[contact.ID()] = contact
	c.contactNicknames[contact.Nickname] = contact
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

// XXX do we even need this method?
func (c *Client) GetContacts() map[string]*Contact {
	getContactsOp := opGetContacts{
		responseChan: make(chan map[string]*Contact),
	}
	c.opCh <- &getContactsOp
	return <-getContactsOp.responseChan
}

// RemoveContact removes a contact from the Client's state.
func (c *Client) RemoveContact(nickname string) {
	c.opCh <- &opRemoveContact{
		name: nickname,
	}
}

func (c *Client) doContactRemoval(nickname string) {
	contact, ok := c.contactNicknames[nickname]
	if !ok {
		c.log.Errorf("contact removal failed, %s not found in contacts", nickname)
		return
	}
	if contact.IsPending {
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
		SpoolReadDescriptor: c.spoolReadDescriptor,
		Contacts:            contacts,
		LinkKey:             c.linkKey,
		User:                c.user,
		Provider:            c.client.Provider(),
		Conversations:       c.GetAllConversations(),
	}
	c.conversationsMutex.Lock()
	defer c.conversationsMutex.Unlock()
	return cbor.Marshal(s)
}

func (c *Client) haltKeyExchanges() {
	for _, contact := range c.contacts {
		if contact.IsPending {
			c.log.Debugf("Halting pending key exchange for '%s' contact.", contact.Nickname)
			if contact.pandaShutdownChan != nil {
				close(contact.pandaShutdownChan)
			}
		}
	}
}

// Shutdown shuts down the client.
func (c *Client) Shutdown() {
	c.log.Info("Shutting down now.")
	c.save()
	c.Halt()
	c.client.Shutdown()
	c.stateWorker.Halt()
	close(c.fatalErrCh)
}

func (c *Client) processPANDAUpdate(update *panda.PandaUpdate) {
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
		c.log.Infof("Key exchange with %s failed: %s", contact.Nickname, update.Err)
		c.eventCh.In() <- &KeyExchangeCompletedEvent{
			Nickname: contact.Nickname,
			Err:      update.Err,
		}
	case update.Serialised != nil:
		if bytes.Equal(contact.pandaKeyExchange, update.Serialised) {
			c.log.Infof("Strange, our PANDA key exchange echoed our exchange bytes: %s", contact.Nickname)
			c.eventCh.In() <- &KeyExchangeCompletedEvent{
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
			c.eventCh.In() <- &KeyExchangeCompletedEvent{
				Nickname: contact.Nickname,
				Err:      err,
			}
			return
		}
		contact.spoolWriteDescriptor = exchange.SpoolWriteDescriptor
		contact.ratchetMutex.Lock()
		err = contact.ratchet.ProcessKeyExchange(exchange.SignedKeyExchange)
		contact.ratchetMutex.Unlock()
		if err != nil {
			err = fmt.Errorf("Double ratchet key exchange failure: %s", err)
			c.log.Error(err.Error())
			contact.pandaResult = err.Error()
			contact.IsPending = false
			c.save()
			c.eventCh.In() <- &KeyExchangeCompletedEvent{
				Nickname: contact.Nickname,
				Err:      err,
			}
			return
		}
		contact.IsPending = false
		c.log.Info("Double ratchet key exchange completed!")
		c.eventCh.In() <- &KeyExchangeCompletedEvent{
			Nickname: contact.Nickname,
		}
	}
	c.save()
}

// SendMessage sends a message to the Client contact with the given nickname.
func (c *Client) SendMessage(nickname string, message []byte) MessageID {
	convoMesgID := MessageID{}
	_, err := rand.Reader.Read(convoMesgID[:])
	if err != nil {
		c.fatalErrCh <- err
	}

	c.opCh <- &opSendMessage{
		id:      convoMesgID,
		name:    nickname,
		payload: message,
	}

	return convoMesgID
}

func (c *Client) doSendMessage(convoMesgID MessageID, nickname string, message []byte) {
	outMessage := Message{
		Plaintext: message,
		Timestamp: time.Now(),
		Outbound:  true,
	}
	c.conversationsMutex.Lock()
	_, ok := c.conversations[nickname]
	if !ok {
		c.conversations[nickname] = make(map[MessageID]*Message)
	}
	c.conversations[nickname][convoMesgID] = &outMessage
	c.conversationsMutex.Unlock()

	contact, ok := c.contactNicknames[nickname]
	if !ok {
		c.log.Errorf("contact %s not found", nickname)
		return
	}
	if contact.IsPending {
		c.log.Errorf("cannot send message, contact %s is pending a key exchange", nickname)
		return
	}

	payload := [DoubleRatchetPayloadLength]byte{}
	binary.BigEndian.PutUint32(payload[:4], uint32(len(message)))
	copy(payload[4:], message)
	contact.ratchetMutex.Lock()
	ciphertext := contact.ratchet.Encrypt(nil, payload[:])
	contact.ratchetMutex.Unlock()
	c.save()

	appendCmd, err := common.AppendToSpool(contact.spoolWriteDescriptor.ID, ciphertext)
	if err != nil {
		c.log.Errorf("failed to compute spool append command: %s", err)
		return
	}
	mesgID, err := c.session.SendUnreliableMessage(contact.spoolWriteDescriptor.Receiver, contact.spoolWriteDescriptor.Provider, appendCmd)
	if err != nil {
		c.log.Errorf("failed to send ciphertext to remote spool: %s", err)
	}
	c.log.Debug("Message enqueued for sending to %s, message-ID: %x", nickname, mesgID)
	c.sendMap.Store(*mesgID, &SentMessageDescriptor{
		Nickname:  nickname,
		MessageID: convoMesgID,
	})
}

func (c *Client) sendReadInbox() {
	sequence := c.spoolReadDescriptor.ReadOffset
	cmd, err := common.ReadFromSpool(c.spoolReadDescriptor.ID, sequence, c.spoolReadDescriptor.PrivateKey)
	if err != nil {
		c.fatalErrCh <- errors.New("failed to compose spool read command")
		return
	}
	_, err = c.session.SendUnreliableMessage(c.spoolReadDescriptor.Receiver, c.spoolReadDescriptor.Provider, cmd)
	if err != nil {
		c.log.Error("failed to send inbox retrieval message")
		return
	}
}

func (c *Client) garbageCollectSendMap(gcEvent *client.MessageIDGarbageCollected) {
	c.log.Debug("Garbage Collecting Message ID %x", gcEvent.MessageID[:])
	c.sendMap.Delete(gcEvent.MessageID)
}

func (c *Client) handleSent(sentEvent *client.MessageSentEvent) {
	rawSentMessageDescriptor, ok := c.sendMap.Load(*sentEvent.MessageID)
	if ok {
		sentMessageDescriptor, typeOK := rawSentMessageDescriptor.(*SentMessageDescriptor)
		if !typeOK {
			c.sendMap.Delete(*sentEvent.MessageID)
			c.fatalErrCh <- errors.New("BUG, sendMap entry has incorrect type.")
			return
		}
		c.eventCh.In() <- &MessageSentEvent{
			Nickname:  sentMessageDescriptor.Nickname,
			MessageID: sentMessageDescriptor.MessageID,
		}
	}
}

func (c *Client) handleReply(replyEvent *client.MessageReplyEvent) {
	defer c.sendMap.Delete(*replyEvent.MessageID)
	spoolResponse, err := common.SpoolResponseFromBytes(replyEvent.Payload)
	if err != nil {
		c.fatalErrCh <- fmt.Errorf("BUG, invalid spool response, error is %s", err)
		return
	}
	if !spoolResponse.IsOK() {
		c.log.Errorf("Spool response status error: %s", spoolResponse.Status)
		return
	}

	// Here we handle replies from sending messages to a contact's remote queue.
	rawSentMessageDescriptor, ok := c.sendMap.Load(*replyEvent.MessageID)
	if ok {
		sentMessageDescriptor, typeOK := rawSentMessageDescriptor.(*SentMessageDescriptor)
		if !typeOK {
			c.fatalErrCh <- errors.New("BUG, sendMap entry has incorrect type.")
			return
		}
		c.eventCh.In() <- &MessageDeliveredEvent{
			Nickname:  sentMessageDescriptor.Nickname,
			MessageID: sentMessageDescriptor.MessageID,
		}
		return
	}
	// Here we handle replies from remote queue message retrievals.
	c.decryptMessage(replyEvent.MessageID, spoolResponse.Message)
}

func (c *Client) GetConversation(nickname string) map[MessageID]*Message {
	c.conversationsMutex.Lock()
	defer c.conversationsMutex.Unlock()
	return c.conversations[nickname]
}

func (c *Client) GetAllConversations() map[string]map[MessageID]*Message {
	c.conversationsMutex.Lock()
	defer c.conversationsMutex.Unlock()
	return c.conversations
}

func (c *Client) decryptMessage(messageID *[cConstants.MessageIDLength]byte, ciphertext []byte) {
	var err error
	message := Message{}
	var decrypted bool
	var nickname string
	for _, contact := range c.contacts {
		contact.ratchetMutex.Lock()
		plaintext, err := contact.ratchet.Decrypt(ciphertext)
		contact.ratchetMutex.Unlock()
		if err != nil {
			c.log.Debugf("Decryption err: %s", err.Error())
			continue
		} else {
			decrypted = true
			nickname = contact.Nickname
			payloadLen := binary.BigEndian.Uint32(plaintext[:4])
			message.Plaintext = plaintext[4 : 4+payloadLen]
			message.Timestamp = time.Now()
			message.Outbound = false
			break
		}
	}
	if decrypted {
		c.spoolReadDescriptor.IncrementOffset() // XXX use a lock or atomic increment?
		convoMesgID := MessageID{}
		_, err := rand.Reader.Read(convoMesgID[:])
		if err != nil {
			c.fatalErrCh <- err
		}
		c.conversationsMutex.Lock()
		defer c.conversationsMutex.Unlock()
		_, ok := c.conversations[nickname]
		if !ok {
			c.conversations[nickname] = make(map[MessageID]*Message)
		}
		c.conversations[nickname][convoMesgID] = &message

		c.eventCh.In() <- &MessageReceivedEvent{
			Nickname:  nickname,
			Message:   message.Plaintext,
			Timestamp: message.Timestamp,
		}
		return
	}
	c.log.Debugf("trial ratchet decryption failure for message ID %x reported ratchet error: %s", messageID, err)
}
