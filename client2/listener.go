// listener.go - Katzenpost server listener.
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

// Package incoming implements the incoming connection support.
package client2

import (
	"container/list"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/charmbracelet/log"

	"github.com/katzenpost/katzenpost/core/worker"
)

type listener struct {
	sync.Mutex
	worker.Worker

	log *log.Logger

	listener *net.UnixListener
	conns    *list.List

	ingressCh chan *Request

	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup
}

func (l *listener) Halt() {
	// Close the listener, wait for worker() to return.
	l.listener.Close()
	l.Worker.Halt()

	// Close all connections belonging to the listener.
	//
	// Note: Worst case this can take up to the handshake timeout to
	// actually complete, since the channel isn't checked mid-handshake.
	close(l.closeAllCh)
	l.closeAllWg.Wait()
}

func (l *listener) worker() {
	addr := l.listener.Addr()
	l.log.Infof("Listening on: %v", addr)
	defer func() {
		l.log.Infof("Stopping listening on: %v", addr)
		l.listener.Close() // Usually redundant, but harmless.
	}()
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				l.log.Errorf("Critical accept failure: %v", err)
				return
			}
			continue
		}

		l.log.Debugf("Accepted new connection: %v", conn.RemoteAddr())

		l.onNewConn(conn.(*net.UnixConn))
	}

	// NOTREACHED
}

func (l *listener) onNewConn(conn *net.UnixConn) {
	c := newIncomingConn(l, conn)

	l.closeAllWg.Add(1)
	l.Lock()
	defer func() {
		l.Unlock()
		go c.worker()
	}()
	c.listElement = l.conns.PushFront(c)
}

func (l *listener) onClosedConn(c *incomingConn) {
	l.Lock()
	defer func() {
		l.Unlock()
		l.closeAllWg.Done()
	}()
	l.conns.Remove(c.listElement)
}

// New creates a new listener.
func NewListener(id int) (*listener, error) {
	var err error

	l := &listener{
		log: log.NewWithOptions(os.Stderr, log.Options{
			ReportTimestamp: true,
			Prefix:          fmt.Sprintf("listener:%d", id),
		}),
		conns:      list.New(),
		closeAllCh: make(chan interface{}),
		ingressCh:  make(chan *Request),
	}

	network := "unixpacket"
	address := "@katzenpost"
	unixAddr, err := net.ResolveUnixAddr(network, address)
	if err != nil {
		return nil, err
	}
	l.listener, err = net.ListenUnix(network, unixAddr)
	if err != nil {
		return nil, err
	}

	l.Go(l.worker)
	return l, nil
}
