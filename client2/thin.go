// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/charmbracelet/log"
	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
)

// ThinResponse is used to encapsulate a message response
// that are passed to the client application.
type ThinResponse struct {

	// SURBID, a unique indentifier for this response,
	// which should precisely match the application's chosen
	// SURBID of the sent message.
	SURBID *[sConstants.SURBIDLength]byte

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

	cfg *config.Config

	log          *log.Logger
	logBackend   *log.Logger
	unixConn     *net.UnixConn
	destUnixAddr *net.UnixAddr

	pkidoc      *cpki.Document
	pkidocMutex sync.RWMutex

	eventSink     chan Event
	drainStop     chan interface{}
	drainStopOnce sync.Once

	isConnected bool

	receivedCh chan ThinResponse
}

// NewThinClient creates a new thing client.
func NewThinClient(cfg *config.Config) *ThinClient {
	return &ThinClient{
		cfg: cfg,
		log: log.NewWithOptions(os.Stderr, log.Options{
			Prefix: "thin_client",
			Level:  log.DebugLevel,
		}),
		logBackend: log.WithPrefix("backend"),
		receivedCh: make(chan ThinResponse),
		eventSink:  make(chan Event),
		drainStop:  make(chan interface{}),
	}
}

func (t *ThinClient) GetConfig() *config.Config {
	return t.cfg
}

func (t *ThinClient) GetLogger(prefix string) *log.Logger {
	return t.logBackend.WithPrefix(prefix)
}

// Close halts the thin client worker thread and closes the socket
// connection with the client daemon.
func (t *ThinClient) Close() error {
	err := t.unixConn.Close()
	close(t.receivedCh)
	t.Worker.Halt()
	return err
}

// Dial dials the client daemon via our agreed upon abstract unix domain socket.
func (t *ThinClient) Dial() error {
	t.log.Debug("Dial begin")
	uniqueID := make([]byte, 4)
	_, err := rand.Reader.Read(uniqueID)
	if err != nil {
		return err
	}

	srcUnixAddr, err := net.ResolveUnixAddr("unixpacket", fmt.Sprintf("@katzenpost_golang_thin_client_%x", uniqueID))
	if err != nil {
		return err
	}

	t.destUnixAddr, err = net.ResolveUnixAddr("unixpacket", "@katzenpost")
	if err != nil {
		return err
	}

	t.log.Debugf("Dial unixpacket %s %s", srcUnixAddr, t.destUnixAddr)
	t.unixConn, err = net.DialUnix("unixpacket", srcUnixAddr, t.destUnixAddr)
	if err != nil {
		return err
	}

	// WAIT UNTIL we have a Noise cryptographic connection with an edge node
	t.log.Debugf("Waiting for a connection status message")
	message1, err := t.readNextMessage()
	if err != nil {
		return err
	}
	if !message1.IsStatus {
		panic("did not receive a connection status message")
	}
	if !message1.IsConnected {
		return errors.New("not connected")
	}

	t.log.Debugf("Waiting for a PKI doc message")
	message2, err := t.readNextMessage()
	if err != nil {
		return err
	}
	t.parsePKIDoc(message2.Payload)
	t.Go(t.worker)
	t.Go(t.eventSinkDrain)
	t.log.Debug("Dial end")
	return nil
}

func (t *ThinClient) worker() {
	for {
		select {
		case <-t.HaltCh():
			return
		default:
		}

		t.log.Debug("-----------------------------BEFORE readNextMessage")
		message, err := t.readNextMessage()
		t.log.Debug("-----------------------------AFTER readNextMessage")
		if err != nil {
			t.log.Infof("thin client ReceiveMessage failed: %v", err)
		}
		if message == nil {
			return
		}

		t.log.Debug("THIN CLIENT WORKER RECEIVED A MESSAGE---------------------")

		switch {
		case message.IsStatus == true:
			t.isConnected = message.IsConnected
			event := &ConnectionStatusEvent{
				IsConnected: message.IsConnected,
			}
			select {
			case t.eventSink <- event:
				continue
			case <-t.HaltCh():
				return
			}
		case message.IsPKIDoc == true:
			doc, err := t.parsePKIDoc(message.Payload)
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
		default:
			if message.Payload == nil {
				t.log.Infof("message.Payload is nil")
			}
			event := &MessageReplyEvent{
				MessageID: message.ID,
				Payload:   message.Payload,
				Err:       nil,
			}
			select {
			case t.eventSink <- event:
				continue
			case <-t.HaltCh():
				return
			}
			response := ThinResponse{
				SURBID:  message.SURBID,
				ID:      message.ID,
				Payload: message.Payload,
			}
			select {
			case <-t.HaltCh():
				return
			case t.receivedCh <- response:
			}
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
	err := doc.Deserialize(payload)
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
func (t *ThinClient) GetServices(capability string) ([]*ServiceDescriptor, error) {
	doc := t.PKIDocument()
	descriptors := FindServices(capability, doc)
	if len(descriptors) == 0 {
		return nil, errors.New("error, GetService failure, service not found in pki doc")
	}
	return descriptors, nil
}

// GetService returns a randomly selected service
// matching the specified service name
func (t *ThinClient) GetService(serviceName string) (*ServiceDescriptor, error) {
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
	req := new(Request)
	req.WithSURB = false
	req.IsSendOp = true
	req.Payload = payload
	req.DestinationIdHash = destNode
	req.RecipientQueueID = destQueue
	req.IsSendOp = true

	blob, err := cbor.Marshal(req)
	if err != nil {
		return err
	}
	count, _, err := t.unixConn.WriteMsgUnix(blob, nil, t.destUnixAddr)
	if err != nil {
		return err
	}
	if count != len(blob) {
		return fmt.Errorf("SendMessage error: wrote %d instead of %d bytes", count, len(blob))
	}

	return nil
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

	req := new(Request)
	req.WithSURB = true
	req.SURBID = surbID
	req.IsSendOp = true
	req.Payload = payload
	req.DestinationIdHash = destNode
	req.RecipientQueueID = destQueue
	req.IsSendOp = true

	blob, err := cbor.Marshal(req)
	if err != nil {
		return err
	}
	count, _, err := t.unixConn.WriteMsgUnix(blob, nil, t.destUnixAddr)
	if err != nil {
		return err
	}
	if count != len(blob) {
		return fmt.Errorf("SendMessage error: wrote %d instead of %d bytes", count, len(blob))
	}

	return nil
}

func (t *ThinClient) readNextMessage() (*Response, error) {
	buff := make([]byte, 65536)
	msgLen, _, _, _, err := t.unixConn.ReadMsgUnix(buff, nil)
	if err != nil {
		return nil, err
	}

	response := Response{}
	err = cbor.Unmarshal(buff[:msgLen], &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// ResponseChan returns the channel that receives message responses
// from the client daemon, of type ThinResponse.
func (t *ThinClient) ResponseChan() chan ThinResponse {
	return t.receivedCh
}

// ReceiveMessage blocks until a message is received.
// Use ResponseChan instead if you want an async way to receive messages.
func (t *ThinClient) ReceiveMessage() (*[sConstants.SURBIDLength]byte, []byte) {
	resp := <-t.receivedCh
	return resp.SURBID, resp.Payload
}

// ARQSend uses a naive ARQ scheme for error correction in the sending of the message.
func (t *ThinClient) ARQSend(id *[MessageIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) error {
	req := new(Request)
	req.ID = id
	req.WithSURB = true
	req.IsARQSendOp = true
	req.Payload = payload
	req.DestinationIdHash = destNode
	req.RecipientQueueID = destQueue

	blob, err := cbor.Marshal(req)
	if err != nil {
		return err
	}
	count, _, err := t.unixConn.WriteMsgUnix(blob, nil, t.destUnixAddr)
	if err != nil {
		return err
	}
	if count != len(blob) {
		return fmt.Errorf("SendMessage error: wrote %d instead of %d bytes", count, len(blob))
	}

	return nil
}

// ARQReceiveMessage blocks until a message is received.
// Use ResponseChan instead if you want an async way to receive messages.
func (t *ThinClient) ARQReceiveMessage() (*[MessageIDLength]byte, []byte) {
	resp := <-t.receivedCh
	return resp.ID, resp.Payload
}

// BlockingSendReliableMessage blocks until the message is reliably sent and the ARQ reply is received.
func (t *ThinClient) BlockingSendReliableMessage(messageID *[MessageIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) (reply []byte, err error) {
	err = t.ARQSend(messageID, payload, destNode, destQueue)
	if err != nil {
		return nil, err
	}
	id2, reply := t.ARQReceiveMessage()
	if !bytes.Equal(messageID[:], id2[:]) {
		return nil, errors.New("received unexpected ARQ reply")
	}
	return reply, nil
}
