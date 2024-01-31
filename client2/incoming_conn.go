// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"fmt"
	"net"

	"github.com/charmbracelet/log"
	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

var incomingConnID uint64

// incomingConn type is used along with listener type
type incomingConn struct {
	listener *listener
	log      *log.Logger

	unixConn *net.UnixConn
	appID    *[AppIDLength]byte

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
	req := new(thin.Request)
	err = cbor.Unmarshal(buff[:reqLen], &req)
	if err != nil {
		fmt.Printf("error decoding cbor from client: %s\n", err)
		return nil, err
	}
	return FromThinRequest(req, c.appID), nil
}

func (c *incomingConn) handleRequest(req *Request) (*Response, error) {
	c.log.Infof("handleRequest: ID %x, Payload: %x", req.AppID[:], req.Payload)

	req.AppID = c.appID
	c.listener.ingressCh <- req
	return nil, nil
}

func (c *incomingConn) sendPKIDoc(doc *cpki.Document) error {
	doc.StripSignatures()
	blob, err := doc.Serialize()
	if err != nil {
		c.log.Debugf("cbor marshal failed: %s", err.Error())
		return err
	}
	message := &Response{
		NewPKIDocumentEvent: &thin.NewPKIDocumentEvent{
			Payload: blob,
		},
	}
	c.sendToClientCh <- message
	return nil
}

func (c *incomingConn) updateConnectionStatus(status error) {
	message := &Response{
		ConnectionStatusEvent: &thin.ConnectionStatusEvent{
			IsConnected: status == nil,
			Err:         status,
		},
	}
	c.sendToClientCh <- message
}

func (c *incomingConn) sendResponse(r *Response) error {
	response := IntoThinResponse(r)
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
			c.handleRequest(rawReq)
		}
	}
	// NOTREACHED
}

func newIncomingConn(l *listener, conn *net.UnixConn) *incomingConn {

	appid := new([AppIDLength]byte)
	_, err := rand.Reader.Read(appid[:])
	if err != nil {
		panic(err)
	}

	c := &incomingConn{
		listener:          l,
		unixConn:          conn,
		appID:             appid,
		closeConnectionCh: make(chan bool),
		sendToClientCh:    make(chan *Response, 2),
	}

	logLevel, err := log.ParseLevel(l.client.cfg.Logging.Level)
	if err != nil {
		panic(err)
	}
	c.log = log.NewWithOptions(l.logbackend, log.Options{
		ReportTimestamp: true,
		Level:           logLevel,
		Prefix:          fmt.Sprintf("incoming:%x", c.appID[:]),
	})

	c.log.Debugf("New incoming connection. Remove addr: %v assigned App ID: %x", conn.RemoteAddr(), appid[:])

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection list.

	return c
}
