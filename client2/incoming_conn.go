package client2

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/charmbracelet/log"
	"github.com/fxamacker/cbor/v2"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

var incomingConnID uint64

// incomingConn type is used along with listener type
type incomingConn struct {
	listener *listener
	log      *log.Logger

	unixConn *net.UnixConn
	appID    uint64

	closeConnectionCh chan bool
	sendToClientCh    chan *Response
}

func (c *incomingConn) Close() {
	c.closeConnectionCh <- true
}

func (c *incomingConn) recvRequest() (*Request, error) {
	buff := make([]byte, 65536)
	reqLen, _, _, _, err := c.unixConn.ReadMsgUnix(buff, nil)
	if err != nil {
		return nil, err
	}
	req := new(Request)
	err = cbor.Unmarshal(buff[:reqLen], &req)
	if err != nil {
		fmt.Printf("error decoding cbor from client: %s\n", err)
		return nil, err
	}

	return req, nil
}

func (c *incomingConn) handleRequest(req *Request) (*Response, error) {
	c.log.Infof("handleRequest: ID %d, Payload: %x", req.AppID, req.Payload)
	if req.IsEchoOp {
		c.log.Info("echo operation")
		payload := make([]byte, len(req.Payload))
		copy(payload, req.Payload)
		return &Response{
			AppID:   req.AppID,
			Payload: payload,
		}, nil
	}

	if req.IsSendOp {
		c.log.Info("send operation")
		req.AppID = c.appID
		c.listener.ingressCh <- req
		return &Response{
			AppID:   req.AppID,
			Payload: []byte{},
		}, nil
	}

	return nil, errors.New("invalid operation specified")
}

func (c *incomingConn) sendPKIDoc(doc *cpki.Document) error {
	blob, err := cbor.Marshal(doc)
	if err != nil {
		return err
	}
	message := &Response{
		Payload: blob,
	}
	c.sendToClientCh <- message
	return nil
}

func (c *incomingConn) updateConnectionStatus(status error) {
	message := &Response{
		IsStatus:    true,
		IsConnected: status == nil,
	}
	c.sendToClientCh <- message
}

func (c *incomingConn) sendResponse(response *Response) error {
	blob, err := cbor.Marshal(response)
	if err != nil {
		return err
	}
	count, err := c.unixConn.Write(blob)
	if err != nil {
		return err
	}
	if count != len(blob) {
		return fmt.Errorf("sendResponse error: only wrote %d bytes whereas buffer is size %d", count, len(blob))
	}
	return nil
}

func (c *incomingConn) worker() {
	defer func() {
		c.log.Debugf("Closing.")
		c.unixConn.Close()
		c.listener.onClosedConn(c) // Remove from the connection list.
	}()

	// Start reading from the unix socket peer.
	requestCh := make(chan *Request)
	requestCloseCh := make(chan interface{})
	defer close(requestCloseCh)
	go func() {
		defer close(requestCh)
		for {
			rawCmd, err := c.recvRequest()
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				return
			}
			select {
			case requestCh <- rawCmd:
			case <-requestCloseCh:
				// c.worker() is returning for some reason, give up on
				// trying to write the command, and just return.
				return
			}
		}
	}()

	for {
		var rawReq *Request
		var ok bool

		select {
		case message := <-c.sendToClientCh:
			err := c.sendResponse(message)
			if err != nil {
				c.log.Infof("received error sending client a message: %s", err.Error())
			}
		case <-c.listener.closeAllCh:
			// Server is getting shutdown, all connections are being closed.
			return
		case rawReq, ok = <-requestCh:
			// Process incoming requests.
			if !ok {
				return
			}
			c.log.Infof("Received Request from peer application.")
			response, err := c.handleRequest(rawReq)
			if err != nil {
				c.log.Infof("Failed to handle Request: %v", err)
				return
			}

			err = c.sendResponse(response)
			if err != nil {
				c.log.Infof("received error sending Response: %s", err.Error())
			}
		}

	}

	// NOTREACHED
}

func newIncomingConn(l *listener, conn *net.UnixConn) *incomingConn {
	c := &incomingConn{
		listener:          l,
		unixConn:          conn,
		appID:             atomic.AddUint64(&incomingConnID, 1), // Diagnostic only, wrapping is fine.
		closeConnectionCh: make(chan bool),
		sendToClientCh:    make(chan *Response, 2),
	}

	c.log = log.NewWithOptions(os.Stderr, log.Options{
		ReportTimestamp: true,
		Prefix:          fmt.Sprintf("incoming:%d", c.appID),
	})

	c.log.Debugf("New incoming connection: %v", conn.RemoteAddr())

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection list.

	return c
}
