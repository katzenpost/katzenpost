// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/charmbracelet/log"
	"github.com/fxamacker/cbor/v2"

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

	log          *log.Logger
	unixConn     *net.UnixConn
	destUnixAddr *net.UnixAddr

	pkidoc      *cpki.Document
	pkidocMutex sync.RWMutex

	isConnected bool

	receivedCh chan ThinResponse
}

// NewThinClient creates a new thing client.
func NewThinClient() *ThinClient {
	return &ThinClient{
		log: log.NewWithOptions(os.Stderr, log.Options{
			Prefix: "thin_client",
			Level:  log.DebugLevel,
		}),
		receivedCh: make(chan ThinResponse),
	}
}

// Close halts the thin client worker thread and closes the socket
// connection with the client daemon.
func (t *ThinClient) Close() error {
	err := t.unixConn.Close()
	t.Halt()
	return err
}

// Dial dials the client daemon via our agreed upon abstract unix domain socket.
func (t *ThinClient) Dial() error {
	t.log.Debug("Dial begin")
	srcUnixAddr, err := net.ResolveUnixAddr("unixpacket", "@katzenpost_golang_thin_client")
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

		message, err := t.readNextMessage()
		if err != nil {
			t.log.Infof("thin client ReceiveMessage failed: %v", err)
		}
		if message == nil {
			return
		}

		t.log.Debug("THIN CLIENT WORKER RECEIVED A MESSAGE")

		switch {
		case message.IsStatus == true:
			t.isConnected = message.IsConnected
		case message.IsPKIDoc == true:
			t.parsePKIDoc(message.Payload)
		default:
			if message.Payload == nil {
				t.log.Infof("message.Payload is nil")
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

func (t *ThinClient) parsePKIDoc(payload []byte) error {
	doc := &cpki.Document{}
	err := doc.Deserialize(payload)
	if err != nil {
		t.log.Errorf("failed to unmarshal CBOR PKI doc: %s", err.Error())
		return err
	}
	t.pkidocMutex.Lock()
	t.pkidoc = doc
	t.pkidocMutex.Unlock()
	return nil
}

// PKIDocument returns the thin client's current reference to the PKI doc
func (t *ThinClient) PKIDocument() *cpki.Document {
	t.pkidocMutex.RLock()
	defer t.pkidocMutex.RUnlock()
	return t.pkidoc
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

func (t *ThinClient) ARQSend(ID *[MessageIDLength]byte, payload []byte, destNode *[32]byte, destQueue []byte) error {
	req := new(Request)
	req.ID = ID
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
