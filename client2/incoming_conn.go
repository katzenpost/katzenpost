// incoming_conn.go - Katzenpost server incoming connection handler.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package client2

import (
	"container/list"
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/charmbracelet/log"
	"github.com/fxamacker/cbor/v2"
)

var incomingConnID uint64

type incomingConn struct {
	listener *listener
	log      *log.Logger

	netConn     *net.UnixConn
	listElement *list.Element
	id          uint64
	retrySeq    uint32

	closeConnectionCh chan bool
}

func (c *incomingConn) Close() {
	c.closeConnectionCh <- true
}

func (c *incomingConn) RecvRequest() (*Request, error) {
	buff := make([]byte, 65536)
	oob := make([]byte, 65536)
	reqLen, oobLen, _, _, err := c.netConn.ReadMsgUnix(buff, oob)
	if err != nil {
		return nil, err
	}
	if oobLen != 0 {
		log.Infof("client sent %d bytes of oob data\n", oobLen)
	}
	req := new(Request)
	err = cbor.Unmarshal(buff[:reqLen], &req)
	if err != nil {
		fmt.Printf("error decoding cbor from client: %s\n", err)
		return nil, err
	}

	return req, nil
}

func (c *incomingConn) handleRequest(req *Request) error {
	c.log.Infof("handleRequest: ID %d, Operation: %x, Payload: %x\n", req.ID, req.Operation, req.Payload)
	return nil // XXX FIXME
}

func (c *incomingConn) worker() {
	defer func() {
		c.log.Debugf("Closing.")
		c.netConn.Close()
		c.listener.onClosedConn(c) // Remove from the connection list.
	}()

	// Start reading from the unix socket peer.
	requestCh := make(chan *Request)
	requestCloseCh := make(chan interface{})
	defer close(requestCloseCh)
	go func() {
		defer close(requestCh)
		for {
			rawCmd, err := c.RecvRequest()
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

	// Process incoming requests.
	for {
		var rawReq *Request
		var ok bool

		select {
		case <-c.listener.closeAllCh:
			// Server is getting shutdown, all connections are being closed.
			return
		case rawReq, ok = <-requestCh:
			if !ok {
				return
			}
		}

		c.log.Debugf("Received Request from peer application.")
		if err := c.handleRequest(rawReq); err != nil {
			c.log.Debugf("Failed to handle Request: %v", err)
			return
		}
		continue
	}

	// NOTREACHED
}

func newIncomingConn(l *listener, conn *net.UnixConn) *incomingConn {
	c := &incomingConn{
		listener:          l,
		netConn:           conn,
		id:                atomic.AddUint64(&incomingConnID, 1), // Diagnostic only, wrapping is fine.
		closeConnectionCh: make(chan bool),
	}

	c.log = log.NewWithOptions(os.Stderr, log.Options{
		ReportTimestamp: true,
		Prefix:          fmt.Sprintf("incoming:%d", c.id),
	})

	c.log.Debugf("New incoming connection: %v", conn.RemoteAddr())

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection list.

	return c
}
