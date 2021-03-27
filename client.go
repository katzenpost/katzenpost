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
	"sort"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/client"
	cConstants "github.com/katzenpost/client/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
	ratchet "github.com/katzenpost/doubleratchet"
	memspoolclient "github.com/katzenpost/memspool/client"
	"github.com/katzenpost/memspool/common"
	pclient "github.com/katzenpost/panda/client"
	panda "github.com/katzenpost/panda/crypto"
	rClient "github.com/katzenpost/reunion/client"
	rTrans "github.com/katzenpost/reunion/transports/katzenpost"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

var (
	errTrialDecryptionFailed  = errors.New("Trial Decryption Failed")
	errInvalidPlaintextLength = errors.New("Plaintext has invalid payload length")
	errContactNotFound        = errors.New("Contact not found")
	errPendingKeyExchange     = errors.New("Cannot send to contact pending key exchange")
	errBlobNotFound           = errors.New("Blob not found in store")
)

// Client is the mixnet client which interacts with other clients
// and services on the network.
type Client struct {
	worker.Worker

	eventCh     channels.Channel
	EventSink   chan interface{}
	opCh        chan interface{}
	pandaChan   chan panda.PandaUpdate
	reunionChan chan rClient.ReunionUpdate
	fatalErrCh  chan error

	// messageID -> *SentMessageDescriptor
	sendMap *sync.Map

	stateWorker         *StateWriter
	linkKey             *ecdh.PrivateKey
	user                string
	blob                map[string][]byte
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
		Blob:          make(map[string][]byte),
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
		reunionChan:         make(chan rClient.ReunionUpdate),
		pandaChan:           make(chan panda.PandaUpdate),
		fatalErrCh:          make(chan error),
		sendMap:             new(sync.Map),
		contacts:            make(map[uint64]*Contact),
		contactNicknames:    make(map[string]*Contact),
		spoolReadDescriptor: state.SpoolReadDescriptor,
		linkKey:             state.LinkKey,
		user:                state.User,
		conversations:       state.Conversations,
		blob:                state.Blob,
		conversationsMutex:  new(sync.Mutex),
		stateWorker:         stateWorker,
		client:              mixnetClient,
		session:             session,
		log:                 logBackend.GetLogger("catshadow"),
		logBackend:          logBackend,
	}
	for _, contact := range state.Contacts {
		c.contacts[contact.id] = contact
		c.contactNicknames[contact.Nickname] = contact
	}
	return c, nil
}

// Start starts the client worker goroutine and the
// read-inbox worker goroutine.
func (c *Client) Start() {
	c.garbageCollectConversations()
	c.Go(c.eventSinkWorker)
	c.Go(c.worker)
	c.restartContactExchanges()
	c.restartSending()
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

// restart contact exchanges
func (c *Client) restartContactExchanges() {
	pandaCfg := c.session.GetPandaConfig()
	reunionCfg := c.session.GetReunionConfig()
	for _, contact := range c.contacts {
		if contact.IsPending {
			if reunionCfg != nil && reunionCfg.Enable == true {
				transports, err := c.getReunionTransports() // could put outside this loop
				if err != nil {
					// XXX: handle with a UI notification
					c.log.Warningf("Reunion configured, but no transports found")
					break
				}
				for eid, ex := range contact.reunionKeyExchange {
					// see if the transport still exists in current transports
					m := false
					for _, tr := range transports {
						if tr.Recipient == ex.recipient && tr.Provider == ex.provider {
							m = true
							lstr := fmt.Sprintf("reunion with %s at %s@%s", contact.Nickname, tr.Recipient, tr.Provider)
							dblog := c.logBackend.GetLogger(lstr)
							exchange, err := rClient.NewExchangeFromSnapshot(ex.serialized, dblog, tr, c.reunionChan)
							if err != nil {
								c.log.Warningf("Reunion failed: %v", err)
							} else {
								go exchange.Run()
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
			} else if pandaCfg != nil {
				logPandaMeeting := c.logBackend.GetLogger(fmt.Sprintf("PANDA_meetingplace_%s", contact.Nickname))
				meetingPlace := pclient.New(pandaCfg.BlobSize, c.session, logPandaMeeting, pandaCfg.Receiver, pandaCfg.Provider)
				logPandaKx := c.logBackend.GetLogger(fmt.Sprintf("PANDA_keyexchange_%s", contact.Nickname))
				kx, err := panda.UnmarshalKeyExchange(rand.Reader, logPandaKx, meetingPlace, contact.pandaKeyExchange, contact.ID(), c.pandaChan, contact.pandaShutdownChan)
				if err != nil {
					panic(err)
				}
				go kx.Run()
			}
		}
	}
}

func (c *Client) restartSending() {
	for _, contact := range c.contacts {
		if !contact.IsPending {
			if _, err := contact.outbound.Peek(); err == nil {
				// prod worker to start draining contact outbound queue
				c.opCh <- &opRetransmit{contact: contact}
			}
		}
	}
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

// called by worker upon opAddContact
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

	// Use PANDA or Reunion
	pandaCfg := c.session.GetPandaConfig()
	reunionCfg := c.session.GetReunionConfig()

	switch {
	case reunionCfg != nil && pandaCfg != nil:
		// both reunion and panda have a configuration entry, and reunion is enabled
		if reunionCfg.Enable == true {
			return errors.New("One of Reunion OR Panda must be configured, not both")
		}
		fallthrough
	case pandaCfg != nil:
		err = c.doPANDAExchange(contact, sharedSecret)
		if err != nil {
			c.log.Notice("PANDA Failure for %v: %v", contact, err)
			return err
		}
	case reunionCfg != nil:
		contact.reunionKeyExchange = make(map[uint64]boundExchange)
		contact.reunionResult = make(map[uint64]string)
		err = c.doReunion(contact, sharedSecret)
		if err != nil {
			c.log.Notice("Reunion Failure for %v: %v", contact, err)
			return err
		}
	}
	return err
}

func (c *Client) doGetConversation(nickname string, responseChan chan Messages) {
	var msg Messages

	c.conversationsMutex.Lock()
	defer c.conversationsMutex.Unlock()
	cc, ok := c.conversations[nickname]
	if !ok {
		close(responseChan)
		return
	}
	for _, m := range cc {
		msg = append(msg, m)
	}
	// do not block the worker
	go func() {
		sort.Sort(msg)
		responseChan <- msg
	}()
}

func (c *Client) doPANDAExchange(contact *Contact, sharedSecret []byte) error {
	// Use PANDA
	pandaCfg := c.session.GetPandaConfig()
	logPandaClient := c.logBackend.GetLogger(fmt.Sprintf("PANDA_meetingplace_%s", contact.Nickname))
	meetingPlace := pclient.New(pandaCfg.BlobSize, c.session, logPandaClient, pandaCfg.Receiver, pandaCfg.Provider)
	kxLog := c.logBackend.GetLogger(fmt.Sprintf("PANDA_keyexchange_%s", contact.Nickname))
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

func (c *Client) doReunion(contact *Contact, sharedSecret []byte) error {
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
				ex, err := rClient.NewExchange(contact.keyExchange, dblog, tr, contact.ID(), sharedSecret, srv, epoch, c.reunionChan)
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

// GetContacts returns the contacts map.
func (c *Client) GetContacts() map[string]*Contact {
	getContactsOp := opGetContacts{
		responseChan: make(chan map[string]*Contact),
	}
	c.opCh <- &getContactsOp
	return <-getContactsOp.responseChan
}

// RemoveContact removes a contact from the Client's state.
func (c *Client) RemoveContact(nickname string) error {
	removeContactOp := &opRemoveContact{
		name:         nickname,
		responseChan: make(chan error),
	}
	c.opCh <- removeContactOp
	return <-removeContactOp.responseChan
}

// RenameContact changes the name of a contact.
func (c *Client) RenameContact(oldname, newname string) error {
	renameContactOp := &opRenameContact{
		oldname:      oldname,
		newname:      newname,
		responseChan: make(chan error),
	}
	c.opCh <- renameContactOp
	return <-renameContactOp.responseChan
}

func (c *Client) doContactRemoval(nickname string) error {
	contact, ok := c.contactNicknames[nickname]
	if !ok {
		return errContactNotFound
	}
	if contact.IsPending {
		if contact.pandaShutdownChan != nil {
			close(contact.pandaShutdownChan)
		}
	}
	delete(c.contactNicknames, nickname)
	delete(c.contacts, contact.id)
	c.conversationsMutex.Lock()
	if _, ok = c.conversations[nickname]; ok {
		delete(c.conversations, nickname)
	}
	c.conversationsMutex.Unlock()
	c.save()
	return nil
}

func (c *Client) doContactRename(oldname, newname string) error {
	// check to see if oldname exists and newname does not exist
	c.conversationsMutex.Lock()
	defer c.conversationsMutex.Unlock()
	contact, ok := c.contactNicknames[oldname]
	if !ok {
		return errors.New("Contact not found")
	}
	if _, ok := c.contactNicknames[newname]; ok {
		return errors.New("Contact already exists")
	}
	contact.Nickname = newname
	c.contactNicknames[newname] = contact
	c.conversations[newname] = c.conversations[oldname]
	delete(c.conversations, oldname)
	delete(c.contactNicknames, oldname)
	return nil
}

func (c *Client) save() {
	c.log.Debug("Saving statefile.")
	serialized, err := c.marshal()
	if err != nil {
		panic(err)
	}
	c.stateWorker.stateCh <- serialized
}

func (c *Client) marshal() ([]byte, error) {
	contacts := []*Contact{}
	for _, contact := range c.contacts {
		contacts = append(contacts, contact)
	}
	c.conversationsMutex.Lock()
	s := &State{
		SpoolReadDescriptor: c.spoolReadDescriptor,
		Contacts:            contacts,
		LinkKey:             c.linkKey,
		User:                c.user,
		Provider:            c.client.Provider(),
		Conversations:       c.conversations,
		Blob:                c.blob,
	}
	defer c.conversationsMutex.Unlock()
	// XXX: shouldn't we also obtain the ratchet locks as well?
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
	c.Halt()
	c.client.Shutdown()
	c.stateWorker.Halt()
}

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
			c.eventCh.In() <- &KeyExchangeCompletedEvent{
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
			c.eventCh.In() <- &KeyExchangeCompletedEvent{
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
			c.eventCh.In() <- &KeyExchangeCompletedEvent{
				Nickname: contact.Nickname,
				Err:      err,
			}
			return
		}
		// XXX: should purge the reunionResults now...
		contact.keyExchange = nil
		contact.IsPending = false
		c.log.Info("Reunion double ratchet key exchange completed by exchange %v!", update.ExchangeID)
		c.eventCh.In() <- &KeyExchangeCompletedEvent{
			Nickname: contact.Nickname,
		}
	}
	c.save()
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
		err = contact.ratchet.ProcessKeyExchange(exchange.KeyExchange)
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
	if len(message)+4 > DoubleRatchetPayloadLength {
		c.fatalErrCh <- fmt.Errorf("Message too large to transmit")
		return MessageID{}
	}
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
	contact, ok := c.contactNicknames[nickname]
	if !ok {
		c.log.Errorf("contact %s not found", nickname)
		c.eventCh.In() <- &MessageNotSentEvent{
			Nickname:  nickname,
			MessageID: convoMesgID,
			Err:       errContactNotFound,
		}
		return
	}
	if contact.IsPending {
		c.log.Errorf("cannot send message, contact %s is pending a key exchange", nickname)
		c.eventCh.In() <- &MessageNotSentEvent{
			Nickname:  nickname,
			MessageID: convoMesgID,
			Err:       errPendingKeyExchange,
		}
		return
	}
	outMessage := Message{
		Plaintext: message,
		Timestamp: time.Now(),
		Outbound:  true,
	}

	payload := [DoubleRatchetPayloadLength]byte{}
	payloadLen := len(message)
	if payloadLen > DoubleRatchetPayloadLength-4 {
		payloadLen = DoubleRatchetPayloadLength - 4
	}
	binary.BigEndian.PutUint32(payload[:4], uint32(payloadLen))
	copy(payload[4:], message)
	contact.ratchetMutex.Lock()
	ciphertext, err := contact.ratchet.Encrypt(nil, payload[:])
	if err != nil {
		c.log.Errorf("failed to encrypt: %s", err)
		contact.ratchetMutex.Unlock()
		c.eventCh.In() <- &MessageNotSentEvent{
			Nickname:  nickname,
			MessageID: convoMesgID,
			Err:       err,
		}
		return
	}
	contact.ratchetMutex.Unlock()

	appendCmd, err := common.AppendToSpool(contact.spoolWriteDescriptor.ID, ciphertext)
	if err != nil {
		c.log.Errorf("failed to compute spool append command: %s", err)
		c.eventCh.In() <- &MessageNotSentEvent{
			Nickname:  nickname,
			MessageID: convoMesgID,
			Err:       err,
		}
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
		c.eventCh.In() <- &MessageNotSentEvent{
			Nickname:  nickname,
			MessageID: convoMesgID,
			Err:       err,
		}
		return
	}

	// update the conversation history
	c.conversationsMutex.Lock()
	_, ok = c.conversations[nickname]
	if !ok {
		c.conversations[nickname] = make(map[MessageID]*Message)
	}
	c.conversations[nickname][convoMesgID] = &outMessage
	c.conversationsMutex.Unlock()
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
				return
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
						Err:       sentEvent.Err,
					}
					c.opCh <- &opRetransmit{contact: contact}
					return
				}

				c.log.Debugf("Sending new msg and resetting timer")
				if contact.rtx != nil {
					contact.rtx.Stop()
				}
				// keep track of the MessageID that has not been ACK'd yet
				contact.ackID = *sentEvent.MessageID
				contact.rtx = time.AfterFunc(sentEvent.ReplyETA*2, func() {
					c.opCh <- &opRetransmit{contact: contact}
				})
			}

			c.log.Debugf("MessageSentEvent for %x", *sentEvent.MessageID)
			c.setMessageSent(tp.Nickname, tp.MessageID)
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
					if contact.ackID != *replyEvent.MessageID {
						// spurious ACK
						c.log.Debugf("Dropping spurious ACK for %x", *replyEvent.MessageID)
						return
					}
					if _, err := contact.outbound.Pop(); err != nil {
						// duplicate ACK?
						c.log.Debugf("Maybe duplicate ACK received for %s with MessageID %x %s",
							contact.Nickname, *replyEvent.MessageID, err)
						return // do not send an extra MessageDeliveredEvent!
					} else {
						// cancel the retransmission timer
						if contact.rtx != nil {
							contact.rtx.Stop()
						}
						// try to send the next message, if one exists
						defer c.sendMessage(contact)
					}
				} else {
					return
				}
				c.log.Debugf("Sending MessageDeliveredEvent for %s", tp.Nickname)
				c.setMessageDelivered(tp.Nickname, tp.MessageID)
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
				c.log.Debugf("Calling decryptMessage(%x, xx)", *replyEvent.MessageID)
				err := c.decryptMessage(replyEvent.MessageID, spoolResponse.Message)
				switch err {
				case errTrialDecryptionFailed:
					// this message did not correspond to any known contacts
					// if we have any contacts pending key exchange, do not increment the spool descriptor
					// in order to avoid losing the first message. this is due to a race where the contact
					// has already completed the key exchange and sent a first message, before we have
					// completed our key exchange.
					// XXX: this could break things if a contact key exchange never completes...
					c.log.Debugf("failure to decrypt tip of spool - MessageID: %x", *replyEvent.MessageID)
					for _, contact := range c.contacts {
						if contact.IsPending {
							c.log.Warning("received message we could not decrypt while key exchange pending, delaying spool read descriptor increment")
							return
						}
					}
					c.log.Warning("received message we could not decrypt while NO key exchange pending, skipping this message")
				case nil:
					// message was decrypted successfully
					c.log.Debugf("successfully decrypted tip of spool - MessageID: %x", *replyEvent.MessageID)
				default:
					// received an error, likely due to retransmission
					c.log.Debugf("failure to decrypt tip of spool - MessageID: %x, err: %s", *replyEvent.MessageID, err.Error())
				}
				// in all other cases, advance the spool read descriptor
				c.spoolReadDescriptor.IncrementOffset()
				c.save()
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

// GetConversation returns a map of messages between a contact
func (c *Client) GetConversation(nickname string) map[MessageID]*Message {
	c.conversationsMutex.Lock()
	defer c.conversationsMutex.Unlock()
	return c.conversations[nickname]
}

// GetConversation returns a map of all the maps of messages between a contact
func (c *Client) GetAllConversations() map[string]map[MessageID]*Message {
	c.conversationsMutex.Lock()
	defer c.conversationsMutex.Unlock()
	return c.conversations
}

// GetSortedConversation returns Messages (a slice of *Message, sorted by Timestamp)
func (c *Client) GetSortedConversation(nickname string) Messages {
	getConversationOp := opGetConversation{
		name:         nickname,
		responseChan: make(chan Messages),
	}
	c.opCh <- &getConversationOp
	m, ok := <-getConversationOp.responseChan
	if !ok {
		return nil
	}
	return m
}

func (c *Client) decryptMessage(messageID *[cConstants.MessageIDLength]byte, ciphertext []byte) error {
	var err error
	message := Message{}
	decrypted := false
	var nickname string
	for _, contact := range c.contacts {
		if contact.IsPending {
			continue
		}
		contact.ratchetMutex.Lock()
		plaintext, err := contact.ratchet.Decrypt(ciphertext)
		contact.ratchetMutex.Unlock()
		switch err {
		case ratchet.ErrCannotDecrypt:
			// this contact could not decrypt the message, try another
			continue
		case nil:
			// message decrypted successfully
			decrypted = true
			nickname = contact.Nickname
			if len(plaintext) < 4 {
				// short plaintext received
				return errInvalidPlaintextLength
			}
			payloadLen := binary.BigEndian.Uint32(plaintext[:4])
			if payloadLen+4 > uint32(len(plaintext)) {
				return errInvalidPlaintextLength
			}
			message.Plaintext = plaintext[4 : 4+payloadLen]
			message.Timestamp = time.Now()
			message.Outbound = false
			break
		default:
			// every other type of error indicates an invalid message
			c.log.Debugf("Decryption err: %s", err.Error())
			return err
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
		_, ok := c.conversations[nickname]
		if !ok {
			c.conversations[nickname] = make(map[MessageID]*Message)
		}
		c.conversations[nickname][convoMesgID] = &message
		c.conversationsMutex.Unlock()
		c.save()

		c.eventCh.In() <- &MessageReceivedEvent{
			Nickname:  nickname,
			Message:   message.Plaintext,
			Timestamp: message.Timestamp,
		}
		return nil
	}
	c.log.Debugf("trial ratchet decryption failure for message ID %x reported ratchet error: %s", *messageID, err)
	return errTrialDecryptionFailed
}

// setMessageSent sets Message MessageID Sent = true and returns true on success
func (c *Client) setMessageSent(nickname string, msgId MessageID) bool {
	c.conversationsMutex.Lock()
	defer c.conversationsMutex.Unlock()
	if ch, ok := c.conversations[nickname]; ok {
		if m, ok := ch[msgId]; ok {
			m.Sent = true
			return true
		}
	}

	return false
}

// setMessageDelivered sets Message MessageID Delivered = true and returns true on success
func (c *Client) setMessageDelivered(nickname string, msgId MessageID) bool {
	c.conversationsMutex.Lock()
	defer c.conversationsMutex.Unlock()
	if ch, ok := c.conversations[nickname]; ok {
		if m, ok := ch[msgId]; ok {
			m.Delivered = true
			return true
		}
	}

	return false
}

// AddBlob adds a []byte blob identified by id string to the clients storage
func (c *Client) AddBlob(id string, blob []byte) error {
	c.blob[id] = blob
	c.save()
	return nil
}

// AddBlob removes the blob identified by id string or error
func (c *Client) DeleteBlob(id string) error {
	_, ok := c.blob[id]
	if !ok {
		return errBlobNotFound
	}
	delete(c.blob, id)
	c.save()
	return nil
}

// GetBlob returns the blob identified by id string or error
func (c *Client) GetBlob(id string) ([]byte, error) {
	b, ok := c.blob[id]
	if !ok {
		return nil, errBlobNotFound
	}
	return b, nil
}
