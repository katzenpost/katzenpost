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
	"strings"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
)

const MessageIDLength = 16

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

	cfg   *config.Config
	isTCP bool

	log        *logging.Logger
	logBackend *log.Backend

	conn         net.Conn
	destUnixAddr *net.UnixAddr

	pkidoc      *cpki.Document
	pkidocMutex sync.RWMutex

	eventSink     chan Event
	drainStop     chan interface{}
	drainStopOnce sync.Once

	isConnected bool

	// used by BlockingSendReliableMessage only
	sentWaitChanMap  sync.Map // MessageID -> chan error
	replyWaitChanMap sync.Map // MessageID -> chan *MessageReplyEvent

	closeOnce sync.Once
}

func (t *ThinClient) Shutdown() {
	// do other stuff here
	t.Halt()
}

// NewThinClient creates a new thing client.
func NewThinClient(cfg *config.Config) *ThinClient {
	logBackend, err := log.New(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.Disable)
	if err != nil {
		panic(err)
	}
	return &ThinClient{
		isTCP:      strings.HasPrefix(strings.ToLower(cfg.ListenNetwork), "tcp"),
		cfg:        cfg,
		log:        logBackend.GetLogger("thinclient"),
		logBackend: logBackend,
		eventSink:  make(chan Event, 2),
		drainStop:  make(chan interface{}),
	}
}

// GetConfig returns the config
func (t *ThinClient) GetConfig() *config.Config {
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

	network := t.cfg.ListenNetwork
	address := t.cfg.ListenAddress

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
	t.Go(t.eventSinkDrain)
	t.Go(t.worker)
	t.log.Debug("Dial end")
	return nil
}

func (t *ThinClient) writeMessage(request *Request) error {
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
		default:
			t.log.Error("bug: received invalid thin client message")
		}
	}
}

func (t *ThinClient) EventSink() chan Event {
	t.stopDrain()
	return t.eventSink
}

func (t *ThinClient) stopDrain() {
	t.drainStopOnce.Do(func() {
		close(t.drainStop)
	})
}

// drain the eventSink until stopDrain() is called
func (t *ThinClient) eventSinkDrain() {
	t.log.Debug("STARTING eventSinkDrain")
	defer t.log.Debug("STOPPING eventSinkDrain")
	for {
		select {
		case <-t.HaltCh():
			// stop thread on shutdown
			return
		case <-t.drainStop:
			// stop thread on drain stop
			return
		case <-t.eventSink:
			continue
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
		return nil, errors.New("context cannot be nil")
	}
	surbID := t.NewSURBID()
	eventSink := t.EventSink()
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
		}

		switch v := event.(type) {
		case *MessageIDGarbageCollected:
			t.log.Info("MessageIDGarbageCollected")
		case *ConnectionStatusEvent:
			t.log.Info("ConnectionStatusEvent")
			if !v.IsConnected {
				panic("socket connection lost")
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
				return nil, errors.New("received MessageReplyEvent with unexpected SURB ID")
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
		return nil, errors.New("context cannot be nil")
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
		return nil, errors.New("halting")
	}

	select {
	case reply := <-replyWaitChan:
		if reply.Err != nil {
			return nil, reply.Err
		}
		return reply.Payload, nil
	case <-t.HaltCh():
		return nil, errors.New("halting")
	}

	// unreachable
}
