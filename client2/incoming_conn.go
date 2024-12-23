// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/thin"
)

var incomingConnID uint64

// incomingConn type is used along with listener type
type incomingConn struct {
	listener *listener
	log      *logging.Logger

	conn  net.Conn
	appID *[AppIDLength]byte

	sendToClientCh chan *Response
}

func (c *incomingConn) recvRequest() (*Request, error) {
	req := new(thin.Request)
	c.log.Debug("recvRequest TCP")
	const prefixLength = 4
	lenPrefix := [prefixLength]byte{}
	count, err := io.ReadFull(c.conn, lenPrefix[:])
	if err != nil {
		return nil, err
	}
	c.log.Debug("read length prefix")
	if count != prefixLength {
		return nil, errors.New("failed to read length prefix")
	}
	blobLen := binary.BigEndian.Uint32(lenPrefix[:])
	c.log.Debugf("length prefix is %d", blobLen)
	blob := make([]byte, blobLen)
	if count, err = io.ReadFull(c.conn, blob); err != nil {
		return nil, err
	}
	c.log.Debug("after blob read")
	if uint32(count) != blobLen {
		return nil, errors.New("failed to read blob")
	}
	c.log.Debug("before Unmarshal")
	err = cbor.Unmarshal(blob[:count], &req)
	if err != nil {
		c.log.Infof("error decoding cbor from client: %s\n", err)
		return nil, err
	}
	c.log.Debug("after Unmarshal")
	return FromThinRequest(req, c.appID), nil
}

func (c *incomingConn) sendPKIDoc(doc []byte) error {
	message := &Response{
		NewPKIDocumentEvent: &thin.NewPKIDocumentEvent{
			Payload: doc,
		},
	}
	select {
	case c.sendToClientCh <- message:
	case <-c.listener.HaltCh():
		return errors.New("shutting down")
	}
	return nil
}

func (c *incomingConn) updateConnectionStatus(status error) {
	message := &Response{
		ConnectionStatusEvent: &thin.ConnectionStatusEvent{
			IsConnected: status == nil,
			Err:         status,
		},
	}
	select {
	case c.sendToClientCh <- message:
	case <-c.listener.HaltCh():
		return
	}
}

func (c *incomingConn) sendResponse(r *Response) error {
	response := IntoThinResponse(r)
	blob, err := cbor.Marshal(response)
	if err != nil {
		return err
	}

	var toSend []byte
	const blobPrefixLen = 4
	prefix := [blobPrefixLen]byte{}
	binary.BigEndian.PutUint32(prefix[:], uint32(len(blob)))
	toSend = append(prefix[:], blob...)

	count, err := c.conn.Write(toSend)
	if err != nil {
		return err
	}
	if count != len(toSend) {
		return fmt.Errorf("sendResponse error: only wrote %d bytes whereas buffer is size %d", count, len(toSend))
	}
	return nil
}

func (c *incomingConn) start() {
	c.listener.Go(c.worker)
}

func (c *incomingConn) worker() {
	defer func() {
		c.log.Debugf("Closing.")
		c.conn.Close()
		c.listener.onClosedConn(c) // Remove from the connection list.
	}()

	// Start reading from the unix socket peer.
	requestCh := make(chan *Request)
	requestCloseCh := make(chan interface{})
	defer close(requestCloseCh)
	c.listener.Go(func() {
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
	})

	c.listener.Go(func() {
		for {
			select {
			case <-c.listener.HaltCh():
				return
			case message := <-c.sendToClientCh:
				err := c.sendResponse(message)
				if err != nil {
					c.log.Infof("received error sending client a message: %s", err.Error())
				}
			}
		}
	})

	for {
		var rawReq *Request
		var ok bool

		select {
		case <-c.listener.HaltCh():
			return
		case rawReq, ok = <-requestCh:
			if !ok {
				return
			}
			if rawReq.IsThinClose {
				c.log.Info("Thin client sent a disconnect request, closing thin client connection.")
				return
			}
			c.log.Infof("Received Request from peer application.")
			select {
			case c.listener.ingressCh <- rawReq:
			case <-c.listener.HaltCh():
				return
			}
		}
	}
	// NOTREACHED
}

func newIncomingConn(l *listener, conn net.Conn) *incomingConn {

	appid := new([AppIDLength]byte)
	_, err := rand.Reader.Read(appid[:])
	if err != nil {
		panic(err)
	}

	c := &incomingConn{
		listener:       l,
		conn:           conn,
		appID:          appid,
		sendToClientCh: make(chan *Response, 2),
	}

	c.log = l.logBackend.GetLogger("client2/incomingConn")
	c.log.Debugf("New incoming connection. Remote addr: %v assigned App ID: %x", conn.RemoteAddr(), appid[:])

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection list.

	return c
}
