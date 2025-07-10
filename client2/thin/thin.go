// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/worker"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

const (
	MessageIDLength = 16
	QueryIDLength   = 16
)

var (
	// Error variables for reuse
	errContextCannotBeNil = errors.New("context cannot be nil")
	errConnectionLost     = errors.New("connection lost")
	errHalting            = errors.New("halting")
)

// ThinResponse is used to encapsulate a message response
// that are passed to the client application.
type ThinResponse struct {

	// SURBID, a unique indentifier for this response,
	// which should precisely match the application's chosen
	// SURBID of the sent message.
	SURBID *[sConstants.SURBIDLength]byte

	// ID is the unique ID for the corresponding sent message.
	ID *[MessageIDLength]byte

	// Payload is the decrypted payload plaintext.
	Payload []byte
}

// ThinClient is the client that handles communication between the mixnet application
// and the client daemon. It does not do any encryption or decryption or checking
// of cryptographic signatures; those responsibilities are left to the client daemon
// process.
type ThinClient struct {
	worker.Worker

	cfg   *Config
	isTCP bool

	log        *logging.Logger
	logBackend *log.Backend

	conn net.Conn

	pkidoc      *cpki.Document
	pkidocMutex sync.RWMutex

	// PKI document cache by epoch to ensure consistency during epoch transitions
	pkiDocCache     map[uint64]*cpki.Document
	pkiDocCacheLock sync.RWMutex

	eventSink   chan Event
	drainAdd    chan chan Event
	drainRemove chan chan Event

	isConnected bool

	// used by BlockingSendReliableMessage only
	sentWaitChanMap  sync.Map // MessageID -> chan error
	replyWaitChanMap sync.Map // MessageID -> chan *MessageReplyEvent
}

// Config is the thin client config.
type Config struct {
	// SphinxGeometry is the Sphinx geometry used by the client daemon that this thin client will connect to.
	SphinxGeometry *geo.Geometry

	// PigeonholeGeometry is the pigeonhole geometry used for payload size validation.
	PigeonholeGeometry *pigeonholeGeo.Geometry

	// Network is the client daemon's listening network.
	Network string

	// Address is the client daemon's listening address.
	Address string
}

func FromConfig(cfg *config.Config) *Config {
	if cfg.SphinxGeometry == nil {
		panic("SphinxGeometry cannot be nil")
	}
	if cfg.PigeonholeGeometry == nil {
		panic("PigeonholeGeometry cannot be nil")
	}

	return &Config{
		SphinxGeometry:     cfg.SphinxGeometry,
		PigeonholeGeometry: cfg.PigeonholeGeometry,
		Network:            cfg.ListenNetwork,
		Address:            cfg.ListenAddress,
	}
}

// LoadFile loads a thin client configuration from a TOML file.
func LoadFile(filename string) (*Config, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	cfg := new(Config)
	err = toml.Unmarshal(b, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// NewThinClient creates a new thing client.
func NewThinClient(cfg *Config, logging *config.Logging) *ThinClient {
	if cfg.SphinxGeometry == nil {
		panic("SphinxGeometry cannot be nil")
	}
	if cfg.PigeonholeGeometry == nil {
		panic("PigeonholeGeometry cannot be nil")
	}

	logBackend, err := log.New(logging.File, logging.Level, logging.Disable)
	if err != nil {
		panic(err)
	}
	return &ThinClient{
		isTCP:       strings.HasPrefix(strings.ToLower(cfg.Network), cfg.Address),
		cfg:         cfg,
		log:         logBackend.GetLogger("thinclient"),
		logBackend:  logBackend,
		eventSink:   make(chan Event, 2),
		drainAdd:    make(chan chan Event),
		drainRemove: make(chan chan Event),
		pkiDocCache: make(map[uint64]*cpki.Document),
	}
}

func (t *ThinClient) Shutdown() {
	t.Halt()
}

// GetConfig returns the config
func (t *ThinClient) GetConfig() *Config {
	return t.cfg
}

// GetLogger(prefix) returns a logger with prefix
func (t *ThinClient) GetLogger(prefix string) *logging.Logger {
	return t.logBackend.GetLogger(prefix)
}

// IsConnected returns true if the daemon is connected to the mixnet
func (t *ThinClient) IsConnected() bool {
	return t.isConnected
}

// Close halts the thin client worker thread and closes the socket
// connection with the client daemon.
func (t *ThinClient) Close() error {

	req := &Request{
		ThinClose: &ThinClose{},
	}
	err := t.writeMessage(req)
	if err != nil {
		return err
	}

	err = t.conn.Close()
	t.Halt()
	close(t.eventSink)
	return err
}

// Dial dials the client daemon
func (t *ThinClient) Dial() error {

	network := t.cfg.Network
	address := t.cfg.Address

	switch network {
	case "tcp6":
		fallthrough
	case "tcp4":
		fallthrough
	case "tcp":
		fallthrough
	case "unix":
		var err error
		t.conn, err = net.Dial(network, address)
		if err != nil {
			return err
		}
	}

	// WAIT for connection status message from daemon
	t.log.Debugf("Waiting for a connection status message")
	message1, err := t.readMessage()
	if err != nil {
		return err
	}
	if message1.ConnectionStatusEvent == nil {
		panic("bug: thin client protocol sequence violation")
	}

	// Set connection state - allow both connected and offline modes
	t.isConnected = message1.ConnectionStatusEvent.IsConnected

	if !t.isConnected {
		t.log.Infof("Daemon is not connected to mixnet - entering offline mode (channel operations will work)")
	} else {
		t.log.Debugf("Daemon is connected to mixnet - full functionality available")
	}

	t.log.Debugf("Waiting for a PKI doc message")
	message2, err := t.readMessage()
	if err != nil {
		return err
	}
	if message2.NewPKIDocumentEvent == nil {
		panic("bug: thin client protocol sequence violation")
	}
	t.parsePKIDoc(message2.NewPKIDocumentEvent.Payload)
	t.Go(t.eventSinkWorker)
	t.Go(t.worker)
	return nil
}

func (t *ThinClient) writeMessage(request *Request) error {
	// Check payload size for SendMessage and SendARQMessage
	var payload []byte
	if request.SendMessage != nil {
		payload = request.SendMessage.Payload
	} else if request.SendARQMessage != nil {
		payload = request.SendARQMessage.Payload
	}
	if payload != nil && len(payload) > t.cfg.SphinxGeometry.UserForwardPayloadLength {
		return fmt.Errorf("payload size %d exceeds maximum allowed size %d", len(payload), t.cfg.SphinxGeometry.UserForwardPayloadLength)
	}

	blob, err := cbor.Marshal(request)
	if err != nil {
		return err
	}

	const blobPrefixLen = 4

	prefix := make([]byte, blobPrefixLen)
	binary.BigEndian.PutUint32(prefix, uint32(len(blob)))
	toSend := append(prefix, blob...)
	count, err := t.conn.Write(toSend)
	if err != nil {
		return err
	}
	if count != len(toSend) {
		return fmt.Errorf("send error: failed to write length prefix: %d != %d", count, len(toSend))
	}
	return nil
}

func (t *ThinClient) readMessage() (*Response, error) {
	const messagePrefixLen = 4

	prefix := make([]byte, messagePrefixLen)
	_, err := io.ReadFull(t.conn, prefix)
	if err != nil {
		return nil, err
	}

	prefixLen := binary.BigEndian.Uint32(prefix)
	message := make([]byte, prefixLen)
	_, err = io.ReadFull(t.conn, message)
	if err != nil {
		return nil, err
	}

	response := &Response{}
	err = cbor.Unmarshal(message, response)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (t *ThinClient) worker() {
	for {
		select {
		case <-t.HaltCh():
			return
		default:
		}

		message, err := t.readMessage()
		if err != nil {
			t.log.Errorf("thin client ReceiveMessage failed: %v", err)
			if err == io.EOF {
				// XXX: should we halt ThinClient on EOF??
				go t.Halt()
				return
			}
			continue
		}
		if message == nil {
			go t.Halt()
			return
		}

		switch {
		case message.ShutdownEvent != nil:
			go t.Halt()
			return
		case message.MessageIDGarbageCollected != nil:
			select {
			case t.eventSink <- message.MessageIDGarbageCollected:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ConnectionStatusEvent != nil:
			select {
			case t.eventSink <- message.ConnectionStatusEvent:
				continue
			case <-t.HaltCh():
				return
			}
		case message.NewPKIDocumentEvent != nil:
			doc, err := t.parsePKIDoc(message.NewPKIDocumentEvent.Payload)
			if err != nil {
				t.log.Errorf("Failed to parse PKI document: %s", err)
				// Gracefully halt the client on PKI parsing failure
				go t.Halt()
				return
			}
			event := &NewDocumentEvent{
				Document: doc,
			}
			select {
			case t.eventSink <- event:
				continue
			case <-t.HaltCh():
				return
			}
		case message.MessageSentEvent != nil:
			isArq := false
			if message.MessageSentEvent.MessageID != nil {
				sentWaitChanRaw, ok := t.sentWaitChanMap.Load(*message.MessageSentEvent.MessageID)
				if ok {
					isArq = true
					sentWaitChan := sentWaitChanRaw.(chan error)
					var err error
					if message.MessageSentEvent.Err != "" {
						err = errors.New(message.MessageSentEvent.Err)
					}
					select {
					case sentWaitChan <- err:
					case <-t.HaltCh():
						return
					}
				}
			}
			if !isArq {
				select {
				case t.eventSink <- message.MessageSentEvent:
					continue
				case <-t.HaltCh():
					return
				}
			}
		case message.MessageReplyEvent != nil:
			if message.MessageReplyEvent.Payload == nil {
				if message.MessageReplyEvent.ErrorCode != ThinClientSuccess {
					t.log.Errorf("message.Payload is nil due to error: %s", ThinClientErrorToString(message.MessageReplyEvent.ErrorCode))
				} else {
					t.log.Error("message.Payload is nil")
				}
			}
			isArq := false
			if message.MessageReplyEvent.MessageID != nil {
				replyWaitChanRaw, ok := t.replyWaitChanMap.Load(*message.MessageReplyEvent.MessageID)
				if ok {
					isArq = true
					replyWaitChan := replyWaitChanRaw.(chan *MessageReplyEvent)
					select {
					case replyWaitChan <- message.MessageReplyEvent:
					case <-t.HaltCh():
						return
					}
				}
			}
			if !isArq {
				select {
				case t.eventSink <- message.MessageReplyEvent:
				case <-t.HaltCh():
					return
				}
			}

		case message.CreateReadChannelReply != nil:
			select {
			case t.eventSink <- message.CreateReadChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.CreateWriteChannelReply != nil:
			select {
			case t.eventSink <- message.CreateWriteChannelReply:
				continue
			case <-t.HaltCh():
				return
			}

		case message.WriteChannelReply != nil:
			select {
			case t.eventSink <- message.WriteChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ReadChannelReply != nil:
			select {
			case t.eventSink <- message.ReadChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ResumeWriteChannelReply != nil:
			select {
			case t.eventSink <- message.ResumeWriteChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ResumeReadChannelReply != nil:
			select {
			case t.eventSink <- message.ResumeReadChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		default:
			t.log.Error("bug: received invalid thin client message")
		}
	}
}

// EventSink returns a channel that receives all Events. The channel should be closed when done.
func (t *ThinClient) EventSink() chan Event {
	// add a new event sink receiver
	ch := make(chan Event, 1)
	t.drainAdd <- ch
	return ch
}

// StopEventSink tells eventSinkWorker to stop sending events to ch
func (t *ThinClient) StopEventSink(ch chan Event) {
	t.drainRemove <- ch
}

// eventSinkWorker adds and removes channels receiving Events
func (t *ThinClient) eventSinkWorker() {
	drains := make(map[chan Event]struct{}, 0)
	for {
		select {
		case <-t.HaltCh():
			// stop thread on shutdown
			return
		case drain := <-t.drainAdd:
			// Only add buffered channels to prevent blocking
			if cap(drain) == 0 {
				t.log.Warning("Attempting to add unbuffered channel to eventSink drains - ignoring")
				continue
			}
			drains[drain] = struct{}{}
		case drain := <-t.drainRemove:
			delete(drains, drain)
		case event := <-t.eventSink:
			bad := make([]chan Event, 0)
			for drain := range drains {
				select {
				case <-t.HaltCh():
					return
				case drain <- event:
					// Successfully sent event
				case <-time.After(100 * time.Millisecond):
					// Channel blocked for too long
					t.log.Warning("Removing unresponsive channel from eventSink drains")
					bad = append(bad, drain)
				}
			}
			// remove blocked drains
			for _, drain := range bad {
				delete(drains, drain)
			}
		}
	}
}

func (t *ThinClient) parsePKIDoc(payload []byte) (*cpki.Document, error) {
	doc := &cpki.Document{}
	err := cbor.Unmarshal(payload, doc)
	if err != nil {
		t.log.Errorf("failed to unmarshal CBOR PKI doc: %s", err.Error())
		return nil, err
	}

	// Update current document
	t.pkidocMutex.Lock()
	t.pkidoc = doc
	t.pkidocMutex.Unlock()

	// Cache document by epoch for consistency during epoch transitions
	t.pkiDocCacheLock.Lock()
	t.pkiDocCache[doc.Epoch] = doc
	t.log.Debugf("Cached PKI document for epoch %d", doc.Epoch)

	// Clean up old cached documents (keep last 5 epochs)
	const maxCachedEpochs = 5
	if len(t.pkiDocCache) > maxCachedEpochs {
		oldestEpoch := doc.Epoch - maxCachedEpochs
		for epoch := range t.pkiDocCache {
			if epoch < oldestEpoch {
				delete(t.pkiDocCache, epoch)
			}
		}
	}
	t.pkiDocCacheLock.Unlock()

	return doc, nil
}

// PKIDocument returns the thin client's current reference to the PKI doc
func (t *ThinClient) PKIDocument() *cpki.Document {
	t.pkidocMutex.RLock()
	defer t.pkidocMutex.RUnlock()
	return t.pkidoc
}

// PKIDocumentForEpoch returns the PKI document for a specific epoch from cache.
// If the document for the requested epoch is not cached, returns the current document.
// This ensures consistency during epoch transitions where Alice and Bob might
// use different PKI documents, leading to different envelope hashes.
func (t *ThinClient) PKIDocumentForEpoch(epoch uint64) (*cpki.Document, error) {
	t.pkiDocCacheLock.RLock()
	defer t.pkiDocCacheLock.RUnlock()
	if doc, exists := t.pkiDocCache[epoch]; exists {
		return doc, nil
	}

	// If the requested epoch is not cached, return the current document
	t.pkidocMutex.RLock()
	currentDoc := t.pkidoc
	t.pkidocMutex.RUnlock()

	if currentDoc != nil {
		return currentDoc, nil
	}

	return nil, errors.New("no PKI document available for the requested epoch")
}

// GetServices returns the services matching the specified service name
func (t *ThinClient) GetServices(capability string) ([]*common.ServiceDescriptor, error) {
	doc := t.PKIDocument()
	descriptors := common.FindServices(capability, doc)
	if len(descriptors) == 0 {
		return nil, errors.New("error, GetService failure, service not found in pki doc")
	}
	return descriptors, nil
}

// GetService returns a randomly selected service
// matching the specified service name
func (t *ThinClient) GetService(serviceName string) (*common.ServiceDescriptor, error) {
	serviceDescriptors, err := t.GetServices(serviceName)
	if err != nil {
		return nil, err
	}
	return serviceDescriptors[rand.NewMath().Intn(len(serviceDescriptors))], nil
}

// NewMessageID returns a new message id.
func (t *ThinClient) NewMessageID() *[MessageIDLength]byte {
	id := new([MessageIDLength]byte)
	_, err := rand.Reader.Read(id[:])
	if err != nil {
		panic(err)
	}
	return id
}

// NewSURBID returns a new surb id.
func (t *ThinClient) NewSURBID() *[sConstants.SURBIDLength]byte {
	id := new([sConstants.SURBIDLength]byte)
	_, err := rand.Reader.Read(id[:])
	if err != nil {
		panic(err)
	}
	return id
}

// NewQueryID returns a new query id.
func (t *ThinClient) NewQueryID() *[QueryIDLength]byte {
	id := new([QueryIDLength]byte)
	_, err := rand.Reader.Read(id[:])
	if err != nil {
		panic(err)
	}
	return id
}

// SendMessageWithoutReply sends a message encapsulated in a Sphinx packet, without any SURB.
// No reply will be possible. This method requires mixnet connectivity.
func (t *ThinClient) SendMessageWithoutReply(payload []byte, destNode *[32]byte, destQueue []byte) error {
	// Check if we're in offline mode
	if !t.isConnected {
		return errors.New("cannot send message in offline mode - daemon not connected to mixnet")
	}

	req := &Request{
		SendMessage: &SendMessage{
			WithSURB:          false,
			Payload:           payload,
			DestinationIdHash: destNode,
			RecipientQueueID:  destQueue,
		},
	}

	return t.writeMessage(req)
}

// SendMessage takes a message payload, a destination node, destination queue ID and a SURB ID and sends a message
// along with a SURB so that you can later receive the reply along with the SURBID you choose.
// This method of sending messages should be considered to be asynchronous because it does NOT actually wait until
// the client daemon sends the message. Nor does it wait for a reply. The only blocking aspect to it's behavior is
// merely blocking until the client daemon receives our request to send a message.
// This method requires mixnet connectivity.
func (t *ThinClient) SendMessage(surbID *[sConstants.SURBIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) error {
	if surbID == nil {
		return errors.New("surbID cannot be nil")
	}

	// Check if we're in offline mode
	if !t.isConnected {
		return errors.New("cannot send message in offline mode - daemon not connected to mixnet")
	}

	req := &Request{
		SendMessage: &SendMessage{
			SURBID:            surbID,
			WithSURB:          true,
			Payload:           payload,
			DestinationIdHash: destNode,
			RecipientQueueID:  destQueue,
		},
	}

	return t.writeMessage(req)
}

// BlockingSendMessage blocks until a reply is received and returns it or an error.
// This method requires mixnet connectivity.
func (t *ThinClient) BlockingSendMessage(ctx context.Context, payload []byte, destNode *[32]byte, destQueue []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}

	// Check if we're in offline mode
	if !t.isConnected {
		return nil, errors.New("cannot send message in offline mode - daemon not connected to mixnet")
	}

	surbID := t.NewSURBID()
	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)
	err := t.SendMessage(surbID, payload, destNode, destQueue)
	if err != nil {
		return nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}

		switch v := event.(type) {
		case *MessageIDGarbageCollected:
			// Ignore garbage collection events
		case *ConnectionStatusEvent:
			if !v.IsConnected {
				panic(errConnectionLost)
			}
		case *NewDocumentEvent:
			// Ignore PKI document updates
		case *MessageSentEvent:
			// Ignore message sent events
		case *MessageReplyEvent:
			if hmac.Equal(surbID[:], v.SURBID[:]) {
				return v.Payload, nil
			} else {
				continue
			}
		default:
			panic("impossible event type")
		}
	}
	// unreachable
}

func (t *ThinClient) SendReliableMessage(messageID *[MessageIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) error {
	// Check if we're in offline mode
	if !t.isConnected {
		return errors.New("cannot send reliable message in offline mode - daemon not connected to mixnet")
	}

	req := &Request{
		SendARQMessage: &SendARQMessage{
			ID:                messageID,
			WithSURB:          true,
			Payload:           payload,
			DestinationIdHash: destNode,
			RecipientQueueID:  destQueue,
		},
	}

	return t.writeMessage(req)
}

// BlockingSendReliableMessage blocks until the message is reliably sent and the ARQ reply is received.
// This method requires mixnet connectivity.
func (t *ThinClient) BlockingSendReliableMessage(ctx context.Context, messageID *[MessageIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) (reply []byte, err error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}

	// Check if we're in offline mode
	if !t.isConnected {
		return nil, errors.New("cannot send reliable message in offline mode - daemon not connected to mixnet")
	}

	if messageID == nil {
		messageID = new([MessageIDLength]byte)
		_, err := io.ReadFull(rand.Reader, messageID[:])
		if err != nil {
			return nil, err
		}
	}

	req := &Request{
		SendARQMessage: &SendARQMessage{
			ID:                messageID,
			WithSURB:          true,
			Payload:           payload,
			DestinationIdHash: destNode,
			RecipientQueueID:  destQueue,
		},
	}

	sentWaitChan := make(chan error)
	t.sentWaitChanMap.Store(*messageID, sentWaitChan)
	defer t.sentWaitChanMap.Delete(*messageID)

	replyWaitChan := make(chan *MessageReplyEvent)
	t.replyWaitChanMap.Store(*messageID, replyWaitChan)
	defer t.replyWaitChanMap.Delete(*messageID)

	err = t.writeMessage(req)
	if err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err = <-sentWaitChan:
		if err != nil {
			return nil, err
		}
	case <-t.HaltCh():
		return nil, errHalting
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case reply := <-replyWaitChan:
		if reply.ErrorCode != ThinClientSuccess {
			return nil, fmt.Errorf("message reply error: %s", ThinClientErrorToString(reply.ErrorCode))
		}
		return reply.Payload, nil
	case <-t.HaltCh():
		return nil, errHalting
	}

	// unreachable
}

/****

NEW PIGEONHOLE CHANNEL API

****/

// CreateWriteChannel creates a new pigeonhole write channel and returns the channel ID, read capability, and write capability.
func (t *ThinClient) CreateWriteChannel(ctx context.Context) (uint16, *bacap.ReadCap, *bacap.WriteCap, error) {
	if ctx == nil {
		return 0, nil, nil, errContextCannotBeNil
	}

	queryID := t.NewQueryID()
	req := &Request{
		CreateWriteChannel: &CreateWriteChannel{
			QueryID: queryID,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return 0, nil, nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, nil, nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, nil, nil, errHalting
		}

		switch v := event.(type) {
		case *CreateWriteChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("CreateWriteChannel: Received CreateWriteChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("CreateWriteChannel: Received CreateWriteChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, nil, nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, v.ReadCap, v.WriteCap, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// CreateReadChannel creates a read channel from a read capability.
func (t *ThinClient) CreateReadChannel(ctx context.Context, readCap *bacap.ReadCap) (uint16, error) {
	if ctx == nil {
		return 0, errContextCannotBeNil
	}
	if readCap == nil {
		return 0, errors.New("readCap cannot be nil")
	}
	queryID := t.NewQueryID()

	req := &Request{
		CreateReadChannel: &CreateReadChannel{
			QueryID: queryID,
			ReadCap: readCap,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return 0, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, errHalting
		}

		switch v := event.(type) {
		case *CreateReadChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("CreateReadChannel: Received CreateReadChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("CreateReadChannel: Received CreateReadChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// WriteChannel prepares a write message for a pigeonhole channel
// and returns the prepared payload and next MessageBoxIndex.
// The thin client must then call SendChannelQuery with the returned payload to actually send the message.
func (t *ThinClient) WriteChannel(ctx context.Context, channelID uint16, payload []byte) (*WriteChannelReply, error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}

	queryID := t.NewQueryID()

	// Validate payload size against pigeonhole geometry
	if len(payload) > t.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength {
		return nil, fmt.Errorf("payload size %d exceeds maximum allowed size %d", len(payload), t.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength)
	}

	req := &Request{
		WriteChannel: &WriteChannel{
			ChannelID: channelID,
			QueryID:   queryID,
			Payload:   payload,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *WriteChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("WriteChannel: Received WriteChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("WriteChannel: Received WriteChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ResumeWriteChannel causes the client daemon to resume to
// a previous state. Note that the last two arguments are optional and can be nil:
// envelopeDescriptor and envelopeHash
func (t *ThinClient) ResumeWriteChannel(
	ctx context.Context,
	writeCap *bacap.WriteCap,
	messageBoxIndex *bacap.MessageBoxIndex,
	envelopeDescriptor []byte,
	envelopeHash *[32]byte) (uint16, error) {

	if ctx == nil {
		return 0, errContextCannotBeNil
	}
	if writeCap == nil {
		return 0, errors.New("writeCap cannot be nil")
	}
	queryID := t.NewQueryID()

	req := &Request{
		ResumeWriteChannel: &ResumeWriteChannel{
			QueryID:            queryID,
			WriteCap:           writeCap,
			MessageBoxIndex:    messageBoxIndex,
			EnvelopeDescriptor: envelopeDescriptor,
			EnvelopeHash:       envelopeHash,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return 0, err
	}
	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *ResumeWriteChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("ResumeWriteChannel: Received ResumeWriteChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("ResumeWriteChannel: Received ResumeWriteChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
	panic("unreachable")
}

// ReadChannel prepares a read query for a pigeonhole channel and
// returns the payload, next MessageBoxIndex, and used ReplyIndex.
// The thin client must then call SendChannelQuery with the
// returned payload to actually send the query.
// The messageBoxIndex and replyIndex parameters are optional and can be nil.
func (t *ThinClient) ReadChannel(ctx context.Context, channelID uint16, messageBoxIndex *bacap.MessageBoxIndex, replyIndex *uint8) (*ReadChannelReply, error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}

	queryID := t.NewQueryID()

	req := &Request{
		ReadChannel: &ReadChannel{
			ChannelID:       channelID,
			QueryID:         queryID,
			MessageBoxIndex: messageBoxIndex,
			ReplyIndex:      replyIndex,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *ReadChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("ReadChannel: Received ReadChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ResumeReadChannel causes the client daemon to resume to
// a previous state. Note that the last two arguments are optional and can be nil:
// envelopeDescriptor and envelopeHash
func (t *ThinClient) ResumeReadChannel(
	ctx context.Context,
	readCap *bacap.ReadCap,
	nextMessageIndex *bacap.MessageBoxIndex,
	replyIndex *uint8,
	envelopeDescriptor []byte,
	envelopeHash *[32]byte) (uint16, error) {

	queryID := t.NewQueryID()
	req := &Request{
		ResumeReadChannel: &ResumeReadChannel{
			QueryID:            queryID,
			ReadCap:            readCap,
			NextMessageIndex:   nextMessageIndex,
			ReplyIndex:         replyIndex,
			EnvelopeDescriptor: envelopeDescriptor,
			EnvelopeHash:       envelopeHash,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)
	err := t.writeMessage(req)
	if err != nil {
		return 0, err
	}
	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *ResumeReadChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("ResumeReadChannel: Received ResumeReadChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("ResumeReadChannel: Received ResumeReadChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
	panic("unreachable")
}

// CloseChannel closes a pigeonhole channel.
func (t *ThinClient) CloseChannel(ctx context.Context, channelID uint16) error {
	if ctx == nil {
		return errContextCannotBeNil
	}

	req := &Request{
		CloseChannel: &CloseChannel{
			ChannelID: channelID,
		},
	}

	return t.writeMessage(req)
}

// SendChannelQuery sends a channel query (prepared by WriteChannel or ReadChannel) to the mixnet.
// This method requires mixnet connectivity and will fail in offline mode.
func (t *ThinClient) SendChannelQuery(
	ctx context.Context,
	channelID uint16,
	payload []byte,
	destNode *[32]byte,
	destQueue []byte,
	messageID *[MessageIDLength]byte,
) error {

	if ctx == nil {
		return errContextCannotBeNil
	}

	// Check if we're in offline mode
	if !t.isConnected {
		return errors.New("cannot send channel query in offline mode - daemon not connected to mixnet")
	}

	surbID := t.NewSURBID()
	req := &Request{
		SendMessage: &SendMessage{
			ID:                messageID,
			ChannelID:         &channelID,
			SURBID:            surbID,
			WithSURB:          true,
			Payload:           payload,
			DestinationIdHash: destNode,
			RecipientQueueID:  destQueue,
		},
	}

	return t.writeMessage(req)
}

func (t *ThinClient) SendChannelQueryAwaitReply(
	ctx context.Context,
	channelID uint16,
	payload []byte,
	destNode *[32]byte,
	destQueue []byte,
	messageID *[MessageIDLength]byte,
) ([]byte, error) {

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.SendChannelQuery(ctx, channelID, payload, destNode, destQueue, messageID)
	if err != nil {
		return nil, err
	}
	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *MessageReplyEvent:
			if v.MessageID == nil {
				t.log.Debugf("SendChannelQueryAwaitReply: Received MessageReplyEvent with nil MessageID, ignoring")
				continue
			}
			if !bytes.Equal(v.MessageID[:], messageID[:]) {
				t.log.Debugf("SendChannelQueryAwaitReply: Received MessageReplyEvent with mismatched MessageID, ignoring")
				continue
			}
			return v.Payload, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

func (t *ThinClient) GetCourierDestination() (*[32]byte, []byte, error) {
	epoch, _, _ := epochtime.Now()
	epochDoc, err := t.PKIDocumentForEpoch(epoch)
	if err != nil {
		return nil, nil, err
	}
	courierServices := common.FindServices("courier", epochDoc)
	if len(courierServices) == 0 {
		return nil, nil, errors.New("no courier services found")
	}
	// Select a random courier service for load distribution
	courierService := courierServices[rand.NewMath().Intn(len(courierServices))]
	destNode := hash.Sum256(courierService.MixDescriptor.IdentityKey)
	destQueue := courierService.RecipientQueueID
	return &destNode, destQueue, nil
}
