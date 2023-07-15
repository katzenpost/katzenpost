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
)

var incomingConnID uint64

type incomingConn struct {
	listener *listener
	log      *log.Logger

	netConn     net.Conn
	listElement *list.Element
	id          uint64
	retrSeq     uint32

	isInitialized bool // Set by listener.

	closeConnectionCh chan bool
}

func (c *incomingConn) Close() {
	c.closeConnectionCh <- true
}

func (c *incomingConn) RecvRequest() (*Request, error) {
	return &Request{}, nil // XXX FIXME
}

func (c *incomingConn) handleRequest(req *Request) error {
	c.log.Infof("do something with the request")
	return nil // XXX FIXME
}

func (c *incomingConn) worker() {
	defer func() {
		c.log.Debugf("Closing.")
		c.netConn.Close()
		c.listener.onClosedConn(c) // Remove from the connection list.
	}()

	c.listener.onInitializedConn(c)

	// Start reading from the peer.
	commandCh := make(chan *Request)
	commandCloseCh := make(chan interface{})
	defer close(commandCloseCh)
	go func() {
		defer close(commandCh)
		for {
			rawCmd, err := c.RecvRequest()
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				return
			}
			select {
			case commandCh <- rawCmd:
			case <-commandCloseCh:
				// c.worker() is returning for some reason, give up on
				// trying to write the command, and just return.
				return
			}
		}
	}()

	// Process incoming packets.
	for {
		var rawReq *Request
		var ok bool

		select {
		case <-c.listener.closeAllCh:
			// Server is getting shutdown, all connections are being closed.
			return
		case rawReq, ok = <-commandCh:
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

func newIncomingConn(l *listener, conn net.Conn) *incomingConn {
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
