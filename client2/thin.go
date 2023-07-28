package client2

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/charmbracelet/log"
	"github.com/fxamacker/cbor/v2"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

type ClientLauncher struct {
	process *os.Process
}

func (l *ClientLauncher) Halt() {
	err := l.process.Signal(syscall.SIGHUP)
	if err != nil {
		panic(err)
	}
	_, err = l.process.Wait()
	if err != nil {
		panic(err)
	}
}

func (l *ClientLauncher) Launch(args ...string) error {
	var procAttr os.ProcAttr
	procAttr.Files = []*os.File{os.Stdin,
		os.Stdout, os.Stderr}
	var err error
	l.process, err = os.StartProcess(args[0], args, &procAttr)
	if err != nil {
		return err
	}
	return nil
}

type ThinClient struct {
	log          *log.Logger
	unixConn     *net.UnixConn
	destUnixAddr *net.UnixAddr
	pkidoc       *cpki.Document
}

func NewThinClient() *ThinClient {
	return &ThinClient{
		log: log.NewWithOptions(os.Stderr, log.Options{
			Prefix: "thin_client",
			Level:  log.DebugLevel,
		}),
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
	message1, err := t.ReceiveMessage()
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
	message2, err := t.ReceiveMessage()
	if err != nil {
		return err
	}
	doc := &cpki.Document{}
	err = cbor.Unmarshal(message2.Payload, doc)
	if err != nil {
		return err
	}

	t.pkidoc = doc

	t.log.Debug("Dial end")

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

func (t *ThinClient) ReceiveMessage() (*Response, error) {
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
