// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
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
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/worker"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

const (
	MessageIDLength = 16
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

	conn         net.Conn
	destUnixAddr *net.UnixAddr

	pkidoc      *cpki.Document
	pkidocMutex sync.RWMutex

	eventSink   chan Event
	drainAdd    chan chan Event
	drainRemove chan chan Event

	isConnected bool

	// used by BlockingSendReliableMessage only
	sentWaitChanMap  sync.Map // MessageID -> chan error
	replyWaitChanMap sync.Map // MessageID -> chan *MessageReplyEvent

	// used by ReadChannel only
	readChannelWaitChanMap sync.Map // MessageID -> chan *ReadChannelReply

	closeOnce sync.Once
}

// Config is the thin client config.
type Config struct {
	// SphinxGeometry is the Sphinx geometry used by the client daemon that this thin client will connect to.
	SphinxGeometry *geo.Geometry

	// PigeonholeGeometry is the pigeonhole geometry used for payload size validation.
	PigeonholeGeometry *replicaCommon.Geometry

	// Network is the client daemon's listening network.
	Network string

	// Address is the client daemon's listening address.
	Address string
}

func FromConfig(cfg *config.Config) *Config {
	if cfg.SphinxGeometry == nil {
		panic("SphinxGeometry cannot be nil")
	}

	nikeScheme := schemes.ByName("CTIDH1024-X25519")
	if nikeScheme == nil {
		panic("failed to get CTIDH1024-X25519 NIKE scheme")
	}

	pigeonholeGeometry := replicaCommon.GeometryFromSphinxGeometry(cfg.SphinxGeometry, nikeScheme)

	return &Config{
		SphinxGeometry:     cfg.SphinxGeometry,
		PigeonholeGeometry: pigeonholeGeometry,
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

// Close halts the thin client worker thread and closes the socket
// connection with the client daemon.
func (t *ThinClient) Close() error {

	req := &Request{
		IsThinClose: true,
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
	t.log.Debug("Dial begin")

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

	// WAIT UNTIL we have a Noise cryptographic connection with an edge node
	t.log.Debugf("Waiting for a connection status message")
	message1, err := t.readMessage()
	if err != nil {
		return err
	}
	if message1.ConnectionStatusEvent == nil {
		panic("bug: thin client protocol sequence violation")
	}
	if !message1.ConnectionStatusEvent.IsConnected {
		return errors.New("not connected")
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
	t.log.Debug("Dial end")
	return nil
}

func (t *ThinClient) writeMessage(request *Request) error {
	if request.Payload != nil && len(request.Payload) > t.cfg.SphinxGeometry.UserForwardPayloadLength {
		return fmt.Errorf("payload size %d exceeds maximum allowed size %d", len(request.Payload), t.cfg.SphinxGeometry.UserForwardPayloadLength)
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
			t.log.Debug("MessageIDGarbageCollected")
			select {
			case t.eventSink <- message.MessageIDGarbageCollected:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ConnectionStatusEvent != nil:
			t.log.Debug("ConnectionStatusEvent")
			select {
			case t.eventSink <- message.ConnectionStatusEvent:
				continue
			case <-t.HaltCh():
				return
			}
		case message.NewPKIDocumentEvent != nil:
			t.log.Debug("NewPKIDocumentEvent")
			doc, err := t.parsePKIDoc(message.NewPKIDocumentEvent.Payload)
			if err != nil {
				t.log.Fatalf("parsePKIDoc %s", err)
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
			t.log.Debug("MessageSentEvent")
			isArq := false
			if message.MessageSentEvent.MessageID != nil {
				sentWaitChanRaw, ok := t.sentWaitChanMap.Load(*message.MessageSentEvent.MessageID)
				if ok {
					isArq = true
					sentWaitChan := sentWaitChanRaw.(chan error)
					select {
					case sentWaitChan <- message.MessageSentEvent.Err:
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
			t.log.Debug("MessageReplyEvent")
			if message.MessageReplyEvent.Payload == nil {
				t.log.Error("message.Payload is nil")
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
		case message.CreateChannelReply != nil:
			t.log.Debug("CreateChannelReply")
			select {
			case t.eventSink <- message.CreateChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.CreateReadChannelReply != nil:
			t.log.Debug("CreateReadChannelReply")
			select {
			case t.eventSink <- message.CreateReadChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.WriteChannelReply != nil:
			t.log.Debug("WriteChannelReply")
			select {
			case t.eventSink <- message.WriteChannelReply:
				continue
			case <-t.HaltCh():
				return
			}
		case message.ReadChannelReply != nil:
			t.log.Debugf("ReadChannelReply: MessageID %x, ChannelID %x, Payload size %d bytes",
				message.ReadChannelReply.MessageID[:], message.ReadChannelReply.ChannelID[:], len(message.ReadChannelReply.Payload))
			isDirectReply := false
			if message.ReadChannelReply.MessageID != nil {
				readWaitChanRaw, ok := t.readChannelWaitChanMap.Load(*message.ReadChannelReply.MessageID)
				if ok {
					isDirectReply = true
					readWaitChan := readWaitChanRaw.(chan *ReadChannelReply)
					select {
					case readWaitChan <- message.ReadChannelReply:
					case <-t.HaltCh():
						return
					}
				} else {
					t.log.Debugf("No wait channel found for MessageID %x", message.ReadChannelReply.MessageID[:])
				}
			}
			if !isDirectReply {
				select {
				case t.eventSink <- message.ReadChannelReply:
					continue
				case <-t.HaltCh():
					return
				}
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
	t.log.Debug("STARTING eventSinkWorker")
	defer t.log.Debug("STOPPING eventSinkWorker")
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
	t.pkidocMutex.Lock()
	t.pkidoc = doc
	t.pkidocMutex.Unlock()
	return doc, nil
}

// PKIDocument returns the thin client's current reference to the PKI doc
func (t *ThinClient) PKIDocument() *cpki.Document {
	t.pkidocMutex.RLock()
	defer t.pkidocMutex.RUnlock()
	return t.pkidoc
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

// SendMessageWithoutReply sends a message encapsulated in a Sphinx packet, without any SURB.
// No reply will be possible.
func (t *ThinClient) SendMessageWithoutReply(payload []byte, destNode *[32]byte, destQueue []byte) error {
	req := &Request{
		WithSURB:          false,
		IsSendOp:          true,
		Payload:           payload,
		DestinationIdHash: destNode,
		RecipientQueueID:  destQueue,
	}

	return t.writeMessage(req)
}

// SendMessage takes a message payload, a destination node, destination queue ID and a SURB ID and sends a message
// along with a SURB so that you can later receive the reply along with the SURBID you choose.
// This method of sending messages should be considered to be asynchronous because it does NOT actually wait until
// the client daemon sends the message. Nor does it wait for a reply. The only blocking aspect to it's behavior is
// merely blocking until the client daemon receives our request to send a message.
func (t *ThinClient) SendMessage(surbID *[sConstants.SURBIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) error {
	if surbID == nil {
		return errors.New("surbID cannot be nil")
	}
	req := &Request{
		SURBID:            surbID,
		WithSURB:          true,
		IsSendOp:          true,
		Payload:           payload,
		DestinationIdHash: destNode,
		RecipientQueueID:  destQueue,
	}

	return t.writeMessage(req)
}

// BlockingSendMessage blocks until a reply is received and returns it or an error.
func (t *ThinClient) BlockingSendMessage(ctx context.Context, payload []byte, destNode *[32]byte, destQueue []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
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
			t.log.Info("MessageIDGarbageCollected")
		case *ConnectionStatusEvent:
			t.log.Info("ConnectionStatusEvent")
			if !v.IsConnected {
				panic(errConnectionLost)
			}
		case *NewDocumentEvent:
			t.log.Info("NewPKIDocumentEvent")
		case *MessageSentEvent:
			t.log.Info("MessageSentEvent")
		case *MessageReplyEvent:
			t.log.Info("MessageReplyEvent")
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
	req := &Request{
		ID:                messageID,
		WithSURB:          true,
		IsARQSendOp:       true,
		Payload:           payload,
		DestinationIdHash: destNode,
		RecipientQueueID:  destQueue,
	}

	return t.writeMessage(req)
}

// BlockingSendReliableMessage blocks until the message is reliably sent and the ARQ reply is received.
func (t *ThinClient) BlockingSendReliableMessage(ctx context.Context, messageID *[MessageIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) (reply []byte, err error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}

	if messageID == nil {
		messageID = new([MessageIDLength]byte)
		_, err := io.ReadFull(rand.Reader, messageID[:])
		if err != nil {
			return nil, err
		}
	}

	req := &Request{
		ID:                messageID,
		WithSURB:          true,
		IsARQSendOp:       true,
		Payload:           payload,
		DestinationIdHash: destNode,
		RecipientQueueID:  destQueue,
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
		if reply.Err != nil {
			return nil, reply.Err
		}
		return reply.Payload, nil
	case <-t.HaltCh():
		return nil, errHalting
	}

	// unreachable
}

// CreateChannel creates a new pigeonhole channel and returns the channel ID and read capability.
func (t *ThinClient) CreateChannel(ctx context.Context) (*[ChannelIDLength]byte, *bacap.UniversalReadCap, error) {
	if ctx == nil {
		return nil, nil, errContextCannotBeNil
	}

	req := &Request{
		CreateChannel: &CreateChannel{},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return nil, nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, nil, errHalting
		}

		switch v := event.(type) {
		case *CreateChannelReply:
			if v.Err != "" {
				return nil, nil, errors.New(v.Err)
			}
			return &v.ChannelID, v.ReadCap, nil
		case *ConnectionStatusEvent:
			if !v.IsConnected {
				return nil, nil, errConnectionLost
			}
		default:
			// Ignore other events
		}
	}
}

// CreateReadChannel creates a read channel from a read capability.
func (t *ThinClient) CreateReadChannel(ctx context.Context, readCap *bacap.UniversalReadCap) (*[ChannelIDLength]byte, error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}
	if readCap == nil {
		return nil, errors.New("readCap cannot be nil")
	}

	req := &Request{
		CreateReadChannel: &CreateReadChannel{
			ReadCap: readCap,
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
		case *CreateReadChannelReply:
			if v.Err != "" {
				return nil, errors.New(v.Err)
			}
			return &v.ChannelID, nil
		case *ConnectionStatusEvent:
			if !v.IsConnected {
				return nil, errConnectionLost
			}
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// WriteChannel writes data to a pigeonhole channel.
func (t *ThinClient) WriteChannel(ctx context.Context, channelID *[ChannelIDLength]byte, payload []byte) error {
	if ctx == nil {
		return errContextCannotBeNil
	}
	if channelID == nil {
		return errors.New("channelID cannot be nil")
	}

	// Validate payload size against pigeonhole geometry
	if len(payload) > t.cfg.PigeonholeGeometry.BoxPayloadLength {
		return fmt.Errorf("payload size %d exceeds maximum allowed size %d", len(payload), t.cfg.PigeonholeGeometry.BoxPayloadLength)
	}

	req := &Request{
		WriteChannel: &WriteChannel{
			ChannelID: *channelID,
			Payload:   payload,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return errHalting
		}

		switch v := event.(type) {
		case *WriteChannelReply:
			if v.Err != "" {
				return errors.New(v.Err)
			}
			return nil
		case *ConnectionStatusEvent:
			if !v.IsConnected {
				return errConnectionLost
			}
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ReadChannel reads data from a pigeonhole channel.
func (t *ThinClient) ReadChannel(ctx context.Context, channelID *[ChannelIDLength]byte, messageID *[MessageIDLength]byte) ([]byte, error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}
	if channelID == nil {
		return nil, errors.New("channelID cannot be nil")
	}
	if messageID == nil {
		return nil, errors.New("messageID cannot be nil")
	}

	req := &Request{
		ID: messageID,
		ReadChannel: &ReadChannel{
			ChannelID: *channelID,
		},
	}

	// Set up direct message ID correlation for ReadChannelReply
	// Always create or reuse a persistent wait channel for this MessageID
	readWaitChanRaw, exists := t.readChannelWaitChanMap.Load(*messageID)
	var readWaitChan chan *ReadChannelReply
	if exists {
		readWaitChan = readWaitChanRaw.(chan *ReadChannelReply)
	} else {
		readWaitChan = make(chan *ReadChannelReply, 1) // Buffered to prevent blocking
		t.readChannelWaitChanMap.Store(*messageID, readWaitChan)
	}

	err := t.writeMessage(req)
	if err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case reply := <-readWaitChan:
		if reply.Err != "" {
			return nil, errors.New(reply.Err)
		}
		return reply.Payload, nil
	case <-t.HaltCh():
		t.readChannelWaitChanMap.Delete(*messageID)
		return nil, errHalting
	}
}

// CopyChannel copies data from a pigeonhole channel to replicas via courier.
func (t *ThinClient) CopyChannel(ctx context.Context, channelID *[ChannelIDLength]byte) error {
	if ctx == nil {
		return errContextCannotBeNil
	}
	if channelID == nil {
		return errors.New("channelID cannot be nil")
	}

	req := &Request{
		CopyChannel: &CopyChannel{
			ChannelID: *channelID,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return errHalting
		}

		switch v := event.(type) {
		case *CopyChannelReply:
			if v.Err != "" {
				return errors.New(v.Err)
			}
			return nil
		case *ConnectionStatusEvent:
			if !v.IsConnected {
				return errConnectionLost
			}
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}
