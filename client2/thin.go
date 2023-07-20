package client2

import (
	"fmt"
	"net"

	"github.com/fxamacker/cbor/v2"
)

type ThinClient struct {
	unixConn     *net.UnixConn
	destUnixAddr *net.UnixAddr
}

func NewThinClient() *ThinClient {
	return &ThinClient{}
}

func (t *ThinClient) Dial() error {
	srcUnixAddr, err := net.ResolveUnixAddr("unixpacket", "@katzenpost_golang_thin_client")
	if err != nil {
		return err
	}

	t.destUnixAddr, err = net.ResolveUnixAddr("unixpacket", "@katzenpost")
	if err != nil {
		return err
	}

	t.unixConn, err = net.DialUnix("unixpacket", srcUnixAddr, t.destUnixAddr)
	if err != nil {
		return err
	}

	return nil
}

func (t *ThinClient) SendMessage(id int, payload []byte, destNode *[32]byte, destQueue []byte) error {
	req := new(Request)
	req.AppID = id
	req.IsSendOp = true
	req.Payload = payload
	req.DestinationIdHash = destNode
	req.RecipientQueueID = destQueue

	blob, err := cbor.Marshal(req)

	count, _, err := t.unixConn.WriteMsgUnix(blob, nil, t.destUnixAddr)
	if err != nil {
		return nil
	}
	if count != len(blob) {
		return fmt.Errorf("SendMessage error: wrote %d instead of %d bytes", count, len(blob))
	}

	return nil
}
