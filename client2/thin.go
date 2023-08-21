package client2

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/charmbracelet/log"
	"github.com/fxamacker/cbor/v2"

	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
)

type ThinClient struct {
	worker.Worker

	log          *log.Logger
	unixConn     *net.UnixConn
	destUnixAddr *net.UnixAddr

	pkidoc      *cpki.Document
	isConnected bool

	receivedCh chan []byte
}

func NewThinClient() *ThinClient {
	return &ThinClient{
		log: log.NewWithOptions(os.Stderr, log.Options{
			Prefix: "thin_client",
			Level:  log.DebugLevel,
		}),
		receivedCh: make(chan []byte),
	}
}

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
		default:
		}

		message, err := t.readNextMessage()
		if err != nil {
			t.log.Infof("thin client ReceiveMessage failed: %s", err.Error())
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
			t.receivedCh <- message.Payload
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
	t.pkidoc = doc
	return nil
}

func (t *ThinClient) PKIDocument() *cpki.Document {
	return t.pkidoc
}

func (t *ThinClient) SendMessage(payload []byte, destNode *[32]byte, destQueue []byte) error {
	req := new(Request)
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

func (t *ThinClient) ReceiveMessage() []byte {
	msg := <-t.receivedCh
	return msg
}
