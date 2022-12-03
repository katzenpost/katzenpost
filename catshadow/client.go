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
	"github.com/awnumar/memguard"
	"sort"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"

	ratchet "github.com/katzenpost/doubleratchet"

	"github.com/katzenpost/katzenpost/client"
	cConstants "github.com/katzenpost/katzenpost/client/constants"
	cUtils "github.com/katzenpost/katzenpost/client/utils"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/core/worker"
	memspoolclient "github.com/katzenpost/katzenpost/memspool/client"
	"github.com/katzenpost/katzenpost/memspool/common"
	"github.com/katzenpost/katzenpost/minclient"
	pclient "github.com/katzenpost/katzenpost/panda/client"
	pCommon "github.com/katzenpost/katzenpost/panda/common"
	panda "github.com/katzenpost/katzenpost/panda/crypto"
	rClient "github.com/katzenpost/katzenpost/reunion/client"
	rTrans "github.com/katzenpost/katzenpost/reunion/transports/katzenpost"
)

var (
	errTrialDecryptionFailed  = errors.New("Trial Decryption Failed")
	errInvalidPlaintextLength = errors.New("Plaintext has invalid payload length")
	errContactNotFound        = errors.New("Contact not found")
	errPendingKeyExchange     = errors.New("Cannot send to contact pending key exchange")
	errProviderNotFound       = errors.New("Cannot find provider")
	errBlobNotFound           = errors.New("Blob not found in store")
	errNoSpool                = errors.New("No Spool Found")
	errNotOnline              = errors.New("Client is not online")
	errNoCurrentDocument      = errors.New("No current document")
	errAlreadyHaveKeyExchange = errors.New("Already created KeyExchange with contact")
	errHalted                 = errors.New("Halted")
	pandaBlobSize             = 1000
)

// Client is the mixnet client which interacts with other clients
// and services on the network.
type Client struct {
	worker.Worker

	eventCh              channels.Channel
	EventSink            chan interface{}
	opCh                 chan interface{}
	pandaChan            chan panda.PandaUpdate
	reunionChan          chan rClient.ReunionUpdate
	fatalErrCh           chan error
	getReadInboxInterval func() time.Duration

	// messageID -> *SentMessageDescriptor
	sendMap *sync.Map

	stateWorker         *StateWriter
	blob                map[string][]byte
	contacts            map[uint64]*Contact
	contactNicknames    map[string]*Contact
	spoolReadDescriptor *memspoolclient.SpoolReadDescriptor
	conversations       map[string]map[MessageID]*Message
	conversationsMutex  *sync.Mutex
	blobMutex           *sync.Mutex
	connMutex           *sync.RWMutex

	online     bool
	connecting bool

	client    *client.Client
	session   *client.Session
	providers []*pki.MixDescriptor

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

// NewClientAndRemoteSpool creates and connects a new Client and creates a new
// remote spool for collecting messages destined to this Client. The Client is
// associated with this remote spool and this state is preserved in the
// encrypted statefile, of course.  This constructor of Client is used when
// creating a new Client as opposed to loading the previously saved state for
// an existing Client.
func NewClientAndRemoteSpool(logBackend *log.Backend, mixnetClient *client.Client, stateWorker *StateWriter) (*Client, error) {
	state := &State{
		Blob:          make(map[string][]byte),
		Contacts:      make([]*Contact, 0),
		Conversations: make(map[string]map[MessageID]*Message),
	}
	c, err := New(logBackend, mixnetClient, stateWorker, state)
	if err != nil {
		return nil, err
	}
	c.Start()
	err = c.Online()
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
	if state == nil {
		state = &State{
			Blob:          make(map[string][]byte),
			Contacts:      make([]*Contact, 0),
			Conversations: make(map[string]map[MessageID]*Message),
		}
	}
	if state.Blob == nil {
		state.Blob = make(map[string][]byte)
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
		conversations:       state.Conversations,
		blob:                state.Blob,
		blobMutex:           new(sync.Mutex),
		conversationsMutex:  new(sync.Mutex),
		connMutex:           new(sync.RWMutex),
		stateWorker:         stateWorker,
		client:              mixnetClient,
		log:                 logBackend.GetLogger("catshadow"),
		logBackend:          logBackend,
	}
	for _, contact := range state.Contacts {
		c.contacts[contact.id] = contact
		c.contactNicknames[contact.Nickname] = contact
	}
	return c, nil
}

// sessionEvents() is called by the worker routine. It returns
// events from the established session or nil, if the client is in offline mode
func (c *Client) sessionEvents() chan client.Event {
	c.connMutex.RLock()
	defer c.connMutex.RUnlock()
	if c.session != nil {
		return c.session.EventSink
	}
	return nil
}

// Start starts the client worker goroutine and the
// read-inbox worker goroutine.
func (c *Client) Start() {
	// Start the fatal error watcher.
	go func() {
		err, ok := <-c.fatalErrCh
		if !ok {
			return
		}
		c.log.Warningf("Shutting down due to error: %v", err)
		c.Shutdown()
	}()

	c.garbageCollectConversations()
	c.Go(c.eventSinkWorker)
	c.Go(c.worker)
	for nickname, contact := range c.GetContacts() {
		msgs := c.GetSortedConversation(nickname)
		if len(msgs) > 0 {
			contact.LastMessage = msgs[len(msgs)-1]
		}
	}
	// Shutdown if the client halts for some reason
	go func() {
		c.client.Wait()
		c.Shutdown()
	}()

}

func (c *Client) initKeyExchange(contact *Contact) error {
	if contact.keyExchange != nil {
		return errAlreadyHaveKeyExchange
	}
	signedKeyExchange, err := contact.ratchet.CreateKeyExchange()
	if err != nil {
		return err
	}

	exchange, err := NewContactExchangeBytes(c.spoolReadDescriptor.GetWriteDescriptor(), signedKeyExchange)
	if err != nil {
		return err
	}

	contact.keyExchange = exchange
	return nil
}

func (c *Client) restartKeyExchanges() {
	c.connMutex.RLock()
	defer c.connMutex.RUnlock()

	c.haltKeyExchanges()
	if !c.online {
		return
	}
	if c.spoolReadDescriptor == nil {
		return
	}
	c.restartPANDAExchanges()
	c.restartReunionExchanges()
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
			if err != errAlreadyHaveKeyExchange && err != nil {
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

// restart PANDA exchanges
func (c *Client) restartPANDAExchanges() {
	for _, contact := range c.contacts {
		if contact.IsPending {
			err := c.initKeyExchange(contact)
			if err != errAlreadyHaveKeyExchange && err != nil {
				// skip if a ratchet keyexchange cannot be found or created
				c.log.Errorf("Failed to resume key exchange for %s: %s", contact.Nickname, err)
				continue
			}
			err = c.doPANDAExchange(contact)
			if err != nil {
				c.log.Errorf("Failed to resume key exchange for %s: %s", contact.Nickname, err)
				continue
			}
		}
	}
}

// restart sending messages
func (c *Client) restartSending() {
	for _, contact := range c.contacts {
		if !contact.IsPending {
			if _, err := contact.outbound.Peek(); err == nil {
				// prod worker to start draining contact outbound queue
				select {
				case <-c.HaltCh():
				case c.opCh <- &opRestartSending{contact: contact}:
				}
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
	for nickname, messages := range c.conversations {
		contact := c.contactNicknames[nickname]
		// skip contacts with message expiration disabled
		if contact.messageExpiration == 0 {
			continue
		}
		for mesgID, message := range messages {
			if time.Now().After(message.Timestamp.Add(contact.messageExpiration)) {
				if contact.LastMessage == message {
					contact.LastMessage = nil
				}
				delete(messages, mesgID)
			}
		}
	}
}

// GetPKIDocument() returns the current pki.Document or error
func (c *Client) GetPKIDocument() (*pki.Document, error) {
	r := make(chan interface{}, 1)
	getPKIOp := &opGetPKIDocument{responseChan: r}
	select {
	case <-c.HaltCh():
		return nil, errHalted
	case c.opCh <- getPKIOp:
	}
	select {
	case <-c.HaltCh():
		return nil, errHalted
	case v := <-r:
		switch v := v.(type) {
		case error:
			return nil, v
		case *pki.Document:
			return v, nil
		default:
			panic("Received unexpected type")
		}
	}
}

func (c *Client) doGetPKIDocument() interface{} {
	c.connMutex.RLock()
	defer c.connMutex.RUnlock()

	if !c.online {
		return errNotOnline
		
	} else {
		doc := c.session.CurrentDocument()
		if doc == nil {
			return errNoCurrentDocument
		} else {
			return doc
		}
	}
}

// GetSpoolProviders() returns the set of current spool providers in the pki.Document
func (c *Client) GetSpoolProviders() ([]string, error) {
	op := &opGetSpoolProviders{responseChan: make(chan interface{}, 1)}
	select {
	case <-c.HaltCh():
		return nil, errHalted
	case c.opCh <- op:
	}
	select {
	case <-c.HaltCh():
		return nil, errHalted
	case r := <-op.responseChan:
		switch r := r.(type) {
		case []string:
			return r, nil
		case error:
			return nil, r
		default:
			panic("Unexpected type")
		}
	}
}

func (c *Client) doGetSpoolProviders() interface {} {
	c.connMutex.RLock()
	defer c.connMutex.RUnlock()

	if !c.online || c.session == nil {
		return errNotOnline
	}
	doc := c.session.CurrentDocument()
	if doc == nil {
		return errNoCurrentDocument
	}

	spoolProviders := cUtils.FindServices(common.SpoolServiceName, doc)
	providerNames := make([]string, len(spoolProviders))
	for i, d := range spoolProviders {
		providerNames[i] = d.Provider
	}
	return providerNames
}

// CreateRemoteSpoolOn creates a remote spool for collecting messages
// destined to this Client. This method blocks until the reply from
// the remote spool service is received or the round trip timeout is reached.
func (c *Client) CreateRemoteSpoolOn(provider string) error {
	createSpoolOp := &opCreateSpool{
		provider:     provider,
		responseChan: make(chan error, 1),
	}
	select {
	case <-c.HaltCh():
		return errHalted
	case c.opCh <- createSpoolOp:
	}
	select {
	case <-c.HaltCh():
		return errHalted
	case r := <-createSpoolOp.responseChan:
		return r
	}
}

// CreateRemoteSpool creates a remote spool for collecting messages
// destined to this Client. This method blocks until the reply from
// the remote spool service is received or the round trip timeout is reached.
func (c *Client) CreateRemoteSpool() error {
	createSpoolOp := &opCreateSpool{
		responseChan: make(chan error, 1),
	}
	select {
	case <-c.HaltCh():
		return errHalted
	case c.opCh <- createSpoolOp:
	}
	select {
	case <-c.HaltCh():
		return errHalted
	case r := <-createSpoolOp.responseChan:
		return r
	}
}

func (c *Client) doCreateRemoteSpool(provider string, responseChan chan error) {
	c.connMutex.RLock()
	defer c.connMutex.RUnlock()

	if c.spoolReadDescriptor != nil {
		responseChan <- errors.New("Already have a remote spool")
		return
	}
	if !c.online {
		responseChan <- errNotOnline
		return
	}
	var desc *cUtils.ServiceDescriptor
	var err error
	// if no provider is specified, pick a random one
	if provider == "" {
		desc, err = c.session.GetService(common.SpoolServiceName)
		if err != nil {
			responseChan <- err
			return
		}
	} else {
		// search for the provider by name
		descs, err := c.session.GetServices(common.SpoolServiceName)
		if err != nil {
			responseChan <- err
			return
		}
		for _, d := range descs {
			if d.Name == provider {
				desc = d
				break
			}
		}
		if desc == nil {
			responseChan <- errProviderNotFound
			return
		}
	}
	go func() {
		// NewSpoolReadDescriptor blocks, so we run this in another thread and then use
		// another workerOp to save the spool descriptor.
		spool, err := memspoolclient.NewSpoolReadDescriptor(desc.Name, desc.Provider, c.session)
		if err != nil {
			select {
			case <-c.HaltCh():
				return
			case responseChan <- err:
			}
		}
		// pass the original caller responseChan
		select {
		case <-c.HaltCh():
		case c.opCh <- &opUpdateSpool{descriptor: spool, responseChan: responseChan}:
		}
	}()
}

// NewContact adds a new contact to the Client's state. This starts
// the PANDA protocol instance for this contact where intermediate
// states will be preserved in the encrypted statefile such that
// progress on the PANDA key exchange can be continued at a later
// time after program shutdown or restart.
func (c *Client) NewContact(nickname string, sharedSecret []byte) {
	select {
	case <-c.HaltCh():
	case c.opCh <- &opAddContact{
		name:         nickname,
		sharedSecret: sharedSecret,
	}:
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
	contact, err := NewContact(nickname, c.randID(), sharedSecret)
	if err != nil {
		return err
	}
	c.contacts[contact.ID()] = contact
	c.contactNicknames[contact.Nickname] = contact
	contact.reunionKeyExchange = make(map[uint64]boundExchange)
	contact.reunionResult = make(map[uint64]string)

	c.connMutex.RLock()
	defer c.connMutex.RUnlock()

	if c.online {
		c.initKeyExchange(contact)
		err = c.doPANDAExchange(contact)
		if err != nil {
			c.log.Notice("PANDA Failure for %v: %v", contact, err)
		}

		err = c.doReunion(contact)
		if err != nil {
			c.log.Notice("Reunion Failure for %v: %v", contact, err)
		}
		return err
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
		select {
		case <- c.HaltCh():
		case responseChan <- msg:
		}
	}()
}

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
			return errNoSpool
		}

		kx, err = panda.NewKeyExchange(rand.Reader, kxLog, meetingPlace, sharedRandom, contact.sharedSecret, contact.keyExchange, contact.id, c.pandaChan, contact.pandaShutdownChan)
		if err != nil {
			return err
		}
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

// GetContacts returns the contacts map.
func (c *Client) GetContacts() map[string]*Contact {
	getContactsOp := &opGetContacts{
		responseChan: make(chan map[string]*Contact, 1),
	}
	select {
	case <-c.HaltCh():
		return nil
	case c.opCh <- getContactsOp:
	}
	select {
	case <-c.HaltCh():
		return nil
	case r := <-getContactsOp.responseChan:
		return r
	}
	// unreached ?
	return nil
}

// RemoveContact removes a contact from the Client's state.
func (c *Client) RemoveContact(nickname string) error {
	removeContactOp := &opRemoveContact{
		name:         nickname,
		responseChan: make(chan error, 1),
	}
	select {
	case <-c.HaltCh():
	return errors.New("No Response to RemoveContact")
	case c.opCh <- removeContactOp:
	}
	select {
	case <-c.HaltCh():
	return errors.New("No Response to RemoveContact")
	case r := <-removeContactOp.responseChan:
		return r
	}
	return errors.New("No Response to RemoveContact")
}

// RenameContact changes the name of a contact.
func (c *Client) RenameContact(oldname, newname string) error {
	renameContactOp := &opRenameContact{
		oldname:      oldname,
		newname:      newname,
		responseChan: make(chan error, 1),
	}
	select {
	case <-c.HaltCh():
		return errors.New("No Response to RenameContact")
	case c.opCh <- renameContactOp:
	}
	select {
	case <-c.HaltCh():
		return errors.New("No Response to RenameContact")
	case r := <-renameContactOp.responseChan:
		return r
	}
	return errors.New("No Response to RenameContact")
}

func (c *Client) doContactRemoval(nickname string) error {
	contact, ok := c.contactNicknames[nickname]
	if !ok {
		return errContactNotFound
	}
	contact.haltKeyExchanges()
	delete(c.contactNicknames, nickname)
	delete(c.contacts, contact.id)
	c.doWipeConversation(nickname) // calls c.save()
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
	c.blobMutex.Lock()
	if b, ok := c.blob["avatar://"+oldname]; ok {
		c.blob["avatar://"+newname] = b
		delete(c.blob, "avatar://"+oldname)
	}
	c.blobMutex.Unlock()

	delete(c.conversations, oldname)
	delete(c.contactNicknames, oldname)
	return nil
}

// GetExpiration returns the message expiration of a contact.
func (c *Client) GetExpiration(name string) (time.Duration, error) {
	getExpirationOp := &opGetExpiration{
		name:         name,
		responseChan: make(chan interface{}, 1),
	}
	select {
	case <-c.HaltCh():
	case c.opCh <- getExpirationOp:
	}

	select {
	case <-c.HaltCh():
		return 0, errHalted
	case v := <-getExpirationOp.responseChan:
		switch v := v.(type) {
		case error:
			return 0, v
		case time.Duration:
			return v, nil
		default:
			return 0, errors.New("Unknown")
		}
	}
}

func (c *Client) doGetExpiration(name string, responseChan chan interface{}) {
	c.conversationsMutex.Lock()
	defer c.conversationsMutex.Unlock()
	if contact, ok := c.contactNicknames[name]; !ok {
		select {
		case <-c.HaltCh():
		case responseChan <- errContactNotFound:
		}

	} else {
		select {
		case <-c.HaltCh():
		case responseChan <- contact.messageExpiration:
		}
	}
}

// ChangeExpiration changes the message history expiration of a contact.
func (c *Client) ChangeExpiration(name string, expiration time.Duration) error {
	changeExpirationOp := &opChangeExpiration{
		name:         name,
		expiration:   expiration,
		responseChan: make(chan error, 1),
	}
	select {
	case <-c.HaltCh():
	case c.opCh <- changeExpirationOp:
	}
	select {
	case <-c.HaltCh():
	case r := <-changeExpirationOp.responseChan:
		return r
	}
	return errors.New("No Response to ChangeExpiration ")
}

func (c *Client) doChangeExpiration(name string, expiration time.Duration) error {
	c.conversationsMutex.Lock()
	if contact, ok := c.contactNicknames[name]; !ok {
		c.conversationsMutex.Unlock()
		return errContactNotFound
	} else {
		contact.messageExpiration = expiration
	}
	c.conversationsMutex.Unlock()
	c.garbageCollectConversations()
	c.save()
	return nil
}

func (c *Client) save() {
	c.log.Debug("Saving statefile.")
	serialized, err := c.marshal()
	if err != nil {
		panic(err)
	}
	select {
	case <-c.HaltCh():
	case c.stateWorker.stateCh <- serialized:
	}
}

func (c *Client) marshal() (*memguard.LockedBuffer, error) {
	contacts := []*Contact{}
	for _, contact := range c.contacts {
		contacts = append(contacts, contact)
	}
	c.conversationsMutex.Lock()
	s := &State{
		SpoolReadDescriptor: c.spoolReadDescriptor,
		Contacts:            contacts,
		Conversations:       c.conversations,
		Providers:           c.providers,
		Blob:                c.blob,
	}
	defer c.conversationsMutex.Unlock()
	// XXX: shouldn't we also obtain the ratchet locks as well?
	ms := memguard.NewStream()
	em, _ := cbor.EncOptions{Time: cbor.TimeUnixDynamic}.EncMode()
	e := em.NewEncoder(ms)
	e.Encode(s)
	return ms.Flush()
}

func (c *Client) haltKeyExchanges() {
	for _, contact := range c.contacts {
		contact.haltKeyExchanges()
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
		contact.sharedSecret = nil
		c.eventCh.In() <- &KeyExchangeCompletedEvent{
			Nickname: contact.Nickname,
		}
	}
	c.save()
}

// SendMessage sends a message to the Client contact with the given nickname.
func (c *Client) SendMessage(nickname string, message []byte) MessageID {
	if len(message)+4 > DoubleRatchetPayloadLength {
		return MessageID{}
	}
	convoMesgID := MessageID{}
	_, err := rand.Reader.Read(convoMesgID[:])
	if err != nil {
		c.fatalErrCh <- err
	}

	select {
	case <-c.HaltCh():
	case c.opCh <- &opSendMessage{
		id:      convoMesgID,
		name:    nickname,
		payload: message,
	}:
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

	serialized, err := cbor.Marshal(outMessage)
	if err != nil {
		c.eventCh.In() <- &MessageNotSentEvent{
			Nickname:  nickname,
			MessageID: convoMesgID,
			Err:       err,
		}
		return
	}
	contact.ratchetMutex.Lock()
	ciphertext, err := contact.ratchet.Encrypt(nil, serialized)
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
		c.connMutex.RLock()
		defer c.connMutex.RUnlock()
		if c.online {
			defer c.sendMessage(contact)
		}
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
	c.contactNicknames[nickname].LastMessage = &outMessage
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
	mesgID, err := c.session.SendReliableMessage(cmd.Receiver, cmd.Provider, cmd.Command)
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
	switch err.(type) {
	case *minclient.PKIError:
		c.session.ForceFetchPKI()
		return
	case nil:
	default:
		c.log.Errorf("sendReadInbox failure: %v", err)
		return
	}
	c.log.Debug("Message enqueued for reading remote spool %x:%d, message-ID: %x", c.spoolReadDescriptor.ID, sequence, mesgID)
	var a MessageID
	binary.BigEndian.PutUint32(a[:4], sequence)
	c.sendMap.Store(*mesgID, &ReadMessageDescriptor{MessageID: a})
}

func (c *Client) garbageCollectSendMap(gcEvent *client.MessageIDGarbageCollected) {
	c.log.Debug("Garbage Collecting Message ID %x", gcEvent.MessageID[:])
	c.sendMap.Delete(gcEvent.MessageID)
}

func (c *Client) handleSent(sentEvent *client.MessageSentEvent) {
	orig, ok := c.sendMap.Load(*sentEvent.MessageID)
	if ok {
		switch tp := orig.(type) {
		case *ReadMessageDescriptor:
			if sentEvent.Err != nil {
				c.log.Debugf("readInbox command %x failed with %s", *sentEvent.MessageID, sentEvent.Err)
			} else {
				c.log.Debugf("readInbox command %x sent", *sentEvent.MessageID)
			}
			return
		case *SentMessageDescriptor:
			// since the retransmission occurs per contact
			// set a timer on the contact
			if contact, ok := c.contactNicknames[tp.Nickname]; !ok {
				return
			} else {
				if sentEvent.Err != nil {
					c.log.Debugf("message send for %s failed with err: %s", tp.Nickname, sentEvent.Err)
					c.eventCh.In() <- &MessageNotSentEvent{
						Nickname:  tp.Nickname,
						MessageID: tp.MessageID,
						Err:       sentEvent.Err,
					}
					return
				}
				// keep track of the MessageID that has not been ACK'd yet
				contact.ackID = *sentEvent.MessageID
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
			// Deserialize spoolresponse
			spoolResponse := common.SpoolResponse{}
			err := cbor.Unmarshal(replyEvent.Payload, &spoolResponse)
			if err != nil {
				c.log.Errorf("Could not deserialize SpoolResponse to message ID %d: %s", tp.MessageID, err)
				c.eventCh.In() <- &MessageNotDeliveredEvent{Nickname: tp.Nickname, MessageID: tp.MessageID,
					Err: fmt.Errorf("Invalid spool response: %s", err),
				}
				return
			}

			if !spoolResponse.IsOK() {
				c.log.Errorf("Spool response ID %d status error: %s for SpoolID %x",
					spoolResponse.MessageID, spoolResponse.Status, spoolResponse.SpoolID)

				c.eventCh.In() <- &MessageNotDeliveredEvent{Nickname: tp.Nickname, MessageID: tp.MessageID,
					Err: spoolResponse.StatusAsError(),
				}
				return
			}
			c.log.Debugf("MessageDeliveredEvent for %s MessageID %x", tp.Nickname, *replyEvent.MessageID)
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
					// try to send the next message, if one exists
					defer c.sendMessage(contact)
				}
				c.log.Debugf("Sending MessageDeliveredEvent for %s", tp.Nickname)
				c.setMessageDelivered(tp.Nickname, tp.MessageID)
				c.save()
				c.eventCh.In() <- &MessageDeliveredEvent{Nickname: tp.Nickname, MessageID: tp.MessageID}
				return
			}
		case *ReadMessageDescriptor:
			// Deserialize spoolresponse
			spoolResponse := common.SpoolResponse{}
			err := cbor.Unmarshal(replyEvent.Payload, &spoolResponse)
			if err != nil {
				c.log.Errorf("Could not deserialize SpoolResponse to ReadInbox ID %d: %s", tp.MessageID, err)
				return
			}
			if !spoolResponse.IsOK() {
				c.log.Errorf("Spool response ID %d status error: %s for SpoolID %x",
					spoolResponse.MessageID, spoolResponse.Status, spoolResponse.SpoolID)

				return
			}
			// is a valid response to the tip of our spool, so increment the pointer
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

// WipeConversation removes all messages between a contact
func (c *Client) WipeConversation(nickname string) error {
	wipeConversationOp := opWipeConversation{
		name:         nickname,
		responseChan: make(chan error, 1),
	}
	select {
	case <-c.HaltCh():
	case c.opCh <- &wipeConversationOp:
	}
	select {
	case <-c.HaltCh():
	case r := <-wipeConversationOp.responseChan:
		return r
	}
	return errHalted
}

func (c *Client) doWipeConversation(nickname string) error {
	c.conversationsMutex.Lock()
	defer c.save()
	defer c.conversationsMutex.Unlock()

	if _, ok := c.conversations[nickname]; !ok {
		return errContactNotFound
	}

	for k, m := range c.conversations[nickname] {
		utils.ExplicitBzero(m.Plaintext)
		m.Timestamp = time.Time{}
		m.Outbound = false
		m.Sent = false
		m.Delivered = false
		delete(c.conversations[nickname], k)
	}
	delete(c.conversations, nickname)

	if contact, ok := c.contactNicknames[nickname]; ok {
		contact.LastMessage = nil
	}
	return nil
}

// GetSortedConversation returns Messages (a slice of *Message, sorted by Timestamp)
func (c *Client) GetSortedConversation(nickname string) Messages {
	getConversationOp := opGetConversation{
		name:         nickname,
		responseChan: make(chan Messages, 1),
	}
	select {
	case c.opCh <- &getConversationOp:
	case <-c.HaltCh():
		return nil
	}
	select {
	case <-c.HaltCh():
	case m, ok := <-getConversationOp.responseChan:
		if !ok {
			return nil
		}
		return m
	}
	return nil
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

			// if the message is a cbor-encoded Message, extract the fields
			err := cbor.Unmarshal(plaintext, &message)
			if err != nil {
				// FIXME: sometime soon, we should remove this
				// backwards-compatibility code path which allows receiving
				// messages that were sent and spooled prior to the cbor
				// message upgrade.

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

			}
			message.Outbound = false
			break
		default:
			// every other type of error indicates an invalid message
			c.log.Debugf("Decryption err for %s: %s", contact.Nickname, err.Error())
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
		if !ok || c.conversations[nickname] == nil {
			c.conversations[nickname] = make(map[MessageID]*Message)
		}

		c.conversations[nickname][convoMesgID] = &message
		c.contactNicknames[nickname].LastMessage = &message
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
	// if Client was constructed from an old state file, blob is nil
	c.blobMutex.Lock()
	c.blob[id] = blob
	c.blobMutex.Unlock()
	c.save()
	return nil
}

// DeleteBlob removes the blob identified by id string or error
func (c *Client) DeleteBlob(id string) error {
	c.blobMutex.Lock()
	defer c.blobMutex.Unlock()
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
	c.blobMutex.Lock()
	defer c.blobMutex.Unlock()
	b, ok := c.blob[id]
	if !ok {
		return nil, errBlobNotFound
	}
	return b, nil
}

// Online() brings catshadow online or returns an error
func (c *Client) Online() error {
	// XXX: block until connection or error ?
	r := make(chan error, 1)
	select {
	case <-c.HaltCh():
	case c.opCh <- &opOnline{responseChan: r}:
	}
	select {
	case <-c.HaltCh():
	case r := <-r:
		return r
	}
	return errors.New("Shutdown")
}

// goOnline is called by worker routine when a goOnline is received. currently only a single session is supported.
func (c *Client) goOnline() error {
	c.connMutex.RLock()
	if c.online || c.connecting || c.session != nil {
		c.connMutex.RUnlock()
		return errors.New("Already Connected")
	}
	c.connMutex.RUnlock()

	// set connecting status
	c.connMutex.Lock()
	c.connecting = true
	c.connMutex.Unlock()

	// try to connect
	s, err := c.client.NewTOFUSession()

	// re-obtain lock
	c.connMutex.Lock()
	c.connecting = false
	if err != nil {
		c.online = false
		c.connMutex.Unlock()
		return err
	}
	c.session = s
	c.online = true
	c.connMutex.Unlock()
	// wait for pki document to arrive
	s.WaitForDocument()
	return nil
}

// Offline() tells the client to disconnect from network services and blocks until the client has disconnected.
func (c *Client) Offline() error {
	// TODO: implement some safe shutdown where necessary
	r := make(chan error, 1)
	select {
	case c.opCh <- &opOffline{responseChan: r}:
	case <-c.HaltCh():
	}
	return <-r
}

// SpoolWriteDescriptor() returns the SpoolWriteDescriptor for this client or nil
func (c *Client) SpoolWriteDescriptor() *memspoolclient.SpoolWriteDescriptor {
	r := make(chan *memspoolclient.SpoolWriteDescriptor, 1)
	select {
	case c.opCh <- &opSpoolWriteDescriptor{responseChan: r}:
	case <-c.HaltCh():
	}
	return <-r
}

func (c *Client) getSpoolWriteDescriptor() *memspoolclient.SpoolWriteDescriptor {
	if c.spoolReadDescriptor == nil {
		return nil
	} else {
		return c.spoolReadDescriptor.GetWriteDescriptor()
	}
}

// goOffline is called by worker routine when a goOffline is received
func (c *Client) goOffline() error {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	if c.connecting {
		return errors.New("Offline() does not cancel Online()")
	}

	if !c.online || c.session == nil {
		return errors.New("Already Offline")
	}

	c.session.Shutdown()
	c.online = false
	c.session = nil
	return nil
}
