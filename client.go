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

type queuedSpoolCommand struct {
	Provider string
	Receiver string
	Command  []byte
	ID       MessageID
}

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
	c, err := New(logBackend, mixnetClient, stateWorker, state)
	if err != nil {
		return nil, err
	}
	c.save()
	err = c.CreateRemoteSpool()
	if err != nil {
		return nil, err
	}
	c.save()
	return c, nil
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
			kx, err := panda.UnmarshalKeyExchange(rand.Reader, logPandaKx, meetingPlace, contact.pandaKeyExchange, contact.ID(), c.pandaChan, contact.pandaShutdownChan)
			if err != nil {
				panic(err)
			}
			go kx.Run()
		} else {
			if _, err := contact.outbound.Peek(); err == nil {
				// prod worker to start draining contact outbound queue
				defer func() { c.opCh <- &opRetransmit{contact: contact} }()
			}
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
	// Shutdown if the client halts for some reason
	go func() {
		c.client.Wait()
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

func (c *Client) stopContactTimers() {
	for _, contact := range c.contacts {
		if contact.rtx != nil {
			contact.rtx.Stop()
		}
	}
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
			pandaCfg := c.session.GetPandaConfig()
			if pandaCfg == nil {
				panic("panda failed, must have a panda service configured")
			}

			c.log.Error("PANDA handshake for client %s timed-out; restarting exchange", contact.Nickname)
			logPandaMeeting := c.logBackend.GetLogger(fmt.Sprintf("PANDA_meetingplace_%s", contact.Nickname))
			meetingPlace := pclient.New(pandaCfg.BlobSize, c.session, logPandaMeeting, pandaCfg.Receiver, pandaCfg.Provider)
			logPandaKx := c.logBackend.GetLogger(fmt.Sprintf("PANDA_keyexchange_%s", contact.Nickname))
			kx, err := panda.UnmarshalKeyExchange(rand.Reader, logPandaKx, meetingPlace, contact.pandaKeyExchange, contact.ID(), c.pandaChan, contact.pandaShutdownChan)
			if err != nil {
				panic(err)
			}
			go kx.Run()
		}
		contact.pandaResult = update.Err.Error()
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
		contact.spoolWriteDescriptor = exchange.SpoolWriteDescriptor
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

	appendCmd, err := common.AppendToSpool(contact.spoolWriteDescriptor.ID, ciphertext)
	if err != nil {
		c.log.Errorf("failed to compute spool append command: %s", err)
		return
	}

	// enqueue the message for sending
	item := &queuedSpoolCommand{Receiver: contact.spoolWriteDescriptor.Receiver,
		Provider: contact.spoolWriteDescriptor.Provider,
		Command:  appendCmd, ID: convoMesgID}
	if _, err := contact.outbound.Peek(); err == ErrQueueEmpty {
		// no messages already queued, so call sendMessage immediately
		defer c.sendMessage(contact)
	}
	if err := contact.outbound.Push(item); err != nil {
		c.log.Debugf("Failed to enqueue message!")
		return
	}
	c.save()
}

func (c *Client) sendMessage(contact *Contact) {
	// Transmit the oldest message on tip of queue; it will be Pop'd upon ACK
	cmd, err := contact.outbound.Peek()
	if err == ErrQueueEmpty {
		c.log.Debugf("No messages to send for contact: %s", contact.Nickname)
		return
	}

	// XXX: unfortunately this command does not tell us when to expect the message delivery to have occurred even though minclient knows it...
	mesgID, err := c.session.SendUnreliableMessage(cmd.Receiver, cmd.Provider, cmd.Command)
	if err != nil {
		c.log.Errorf("failed to send ciphertext to remote spool: %s", err)
		return
	}
	c.log.Debug("Message enqueued for sending to %s, message-ID: %x", contact.Nickname, *mesgID)
	c.sendMap.Store(*mesgID, &SentMessageDescriptor{
		Nickname:  contact.Nickname,
		MessageID: cmd.ID,
	})
}

func (c *Client) sendReadInbox() {
	// apparently never checks to see if the spool has been made first...
	if c.spoolReadDescriptor == nil {
		c.log.Errorf("Should not sendReadInbox before the remote spool was made...")
		return
	}
	sequence := c.spoolReadDescriptor.ReadOffset
	cmd, err := common.ReadFromSpool(c.spoolReadDescriptor.ID, sequence, c.spoolReadDescriptor.PrivateKey)
	if err != nil {
		c.fatalErrCh <- errors.New("failed to compose spool read command")
		return
	}
	mesgID, err := c.session.SendUnreliableMessage(c.spoolReadDescriptor.Receiver, c.spoolReadDescriptor.Provider, cmd)
	if err != nil {
		c.log.Error("failed to send inbox retrieval message")
		return
	}
	c.log.Debug("Message enqueued for reading remote spool %x:%d, message-ID: %x", c.spoolReadDescriptor.ID, sequence, mesgID)
	var a MessageID
	binary.BigEndian.PutUint32(a[:4], sequence)
	c.sendMap.Store(*mesgID, &SentMessageDescriptor{Nickname: c.user, MessageID: a})
}

func (c *Client) garbageCollectSendMap(gcEvent *client.MessageIDGarbageCollected) {
	c.log.Debug("Garbage Collecting Message ID %x", gcEvent.MessageID[:])
	c.sendMap.Delete(gcEvent.MessageID)
}

func (c *Client) handleSent(sentEvent *client.MessageSentEvent) {
	orig, ok := c.sendMap.Load(*sentEvent.MessageID)
	if ok {
		switch tp := orig.(type) {
		case *SentMessageDescriptor:
			if tp.Nickname == c.user { // ack for readInbox
				if sentEvent.Err != nil {
					c.log.Debugf("readInbox command %x failed with %s", *sentEvent.MessageID, sentEvent.Err)
				} else {
					c.log.Debugf("readInbox command %x sent", *sentEvent.MessageID)
				}
				return
			}

			// since the retransmission occurs per contact
			// set a timer on the contact
			if contact, ok := c.contactNicknames[tp.Nickname]; !ok {
				panic("contact not found")
			} else {
				if sentEvent.Err != nil {
					c.log.Debugf("message send for %s failed with err: %s", tp.Nickname, sentEvent.Err)
					// XXX: need to do something to resume transmission...
					if contact.rtx != nil {
						contact.rtx.Stop()
					}
					c.eventCh.In() <- &MessageNotSentEvent{
						Nickname:  tp.Nickname,
						MessageID: tp.MessageID,
					}
					c.opCh <- &opRetransmit{contact: contact}
					return
				}

				c.log.Debugf("Sending new msg and resetting timer")
				if contact.rtx != nil {
					contact.rtx.Stop()
				}
				contact.rtx = time.AfterFunc(sentEvent.ReplyETA*2, func() {
					c.opCh <- &opRetransmit{contact: contact}
				})
			}

			c.log.Debugf("MessageSentEvent for %x", *sentEvent.MessageID)
			c.eventCh.In() <- &MessageSentEvent{
				Nickname:  tp.Nickname,
				MessageID: tp.MessageID,
			}
		default:
			c.fatalErrCh <- errors.New("BUG, sendMap entry has incorrect type")
		}
	}
}

func (c *Client) handleReply(replyEvent *client.MessageReplyEvent) {
	if ev, ok := c.sendMap.Load(*replyEvent.MessageID); ok {
		defer c.sendMap.Delete(replyEvent.MessageID)
		switch tp := ev.(type) {
		case *SentMessageDescriptor:
			spoolResponse, err := common.SpoolResponseFromBytes(replyEvent.Payload)
			if err != nil {
				c.fatalErrCh <- fmt.Errorf("BUG, invalid spool response, error is %s", err)
				return
			}
			if !spoolResponse.IsOK() {
				c.log.Errorf("Spool response ID %d status error: %s for SpoolID %x",
					spoolResponse.MessageID, spoolResponse.Status, spoolResponse.SpoolID)
				// XXX: should emit an event to the client ? eg spool write failure
				return
			}
			if tp.Nickname != c.user {
				// Is a Message Delivery acknowledgement for a spool write
				c.log.Debugf("MessageDeliveredEvent for %s MessageID %x", tp.Nickname, *replyEvent.MessageID)
				// cancel retransmission timer
				if contact, ok := c.contactNicknames[tp.Nickname]; ok {
					// cancel the retransmission timer
					if contact.rtx != nil {
						contact.rtx.Stop()
					}
					if _, err := contact.outbound.Pop(); err != nil {
						// duplicate ACK?
						c.log.Debugf("Maybe duplicate ACK received for %s with MessageID %x",
							contact.Nickname, *replyEvent.MessageID)
					} else {
						// try to send the next message, if one exists
						defer c.sendMessage(contact)
					}
				} else {
					panic("contact is missing")
				}
				c.log.Debugf("Sending MessageDeliveredEvent for %s", tp.Nickname)
				c.eventCh.In() <- &MessageDeliveredEvent{
					Nickname:  tp.Nickname,
					MessageID: tp.MessageID,
				}
				return
			}

			// is a valid response to the tip of our spool, so increment the pointer
			off := binary.BigEndian.Uint32(tp.MessageID[:4])

			c.log.Debugf("Got a valid spool response: %d, status: %s, len %d in response to: %d", spoolResponse.MessageID, spoolResponse.Status, len(spoolResponse.Message), off)
			switch {
			case spoolResponse.MessageID < c.spoolReadDescriptor.ReadOffset:
				return // dup
			case spoolResponse.MessageID == c.spoolReadDescriptor.ReadOffset:
				c.spoolReadDescriptor.IncrementOffset()
				c.log.Debugf("Calling decryptMessage(%x, xx)", *replyEvent.MessageID)
				if !c.decryptMessage(replyEvent.MessageID, spoolResponse.Message) {
					c.log.Debugf("failure to decrypt tip of spool - MessageID: %x", *replyEvent.MessageID)
				}
			default:
				panic("received spool response for MessageID not requested yet")
			}
			return
		default:
			c.fatalErrCh <- errors.New("BUG, sendMap entry has incorrect type")
			return
		}
	}
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

func (c *Client) decryptMessage(messageID *[cConstants.MessageIDLength]byte, ciphertext []byte) (decrypted bool) {
	var err error
	message := Message{}
	decrypted = false
	var nickname string
	for _, contact := range c.contacts {
		if contact.IsPending {
			continue
		}
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
		convoMesgID := MessageID{}
		_, err = rand.Reader.Read(convoMesgID[:])
		if err != nil {
			c.fatalErrCh <- err
		}
		c.log.Debugf("Message decrypted for %s: %x", nickname, convoMesgID)
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
	c.log.Debugf("trial ratchet decryption failure for message ID %x reported ratchet error: %s", *messageID, err)
	return
}
