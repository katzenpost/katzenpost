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

package server

import (
	"bytes"
	"container/list"
	"fmt"
	"net"
	"sync"

	"github.com/op/go-logging"
)

type listener struct {
	sync.WaitGroup
	sync.Mutex

	s   *Server
	l   net.Listener
	log *logging.Logger

	conns *list.List

	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup
}

func (l *listener) halt() {
	// Close the listener, wait for worker() to return.
	l.l.Close()
	l.Wait()

	// Close all connections belonging to the listener.
	//
	// Note: Worst case this can take up to the handshake timeout to
	// actually complete, since the channel isn't checked mid-handshake.
	close(l.closeAllCh)
	l.closeAllWg.Wait()
}

func (l *listener) worker() {
	addr := l.l.Addr()
	l.log.Noticef("Listening on: %v", addr)
	defer func() {
		l.log.Noticef("Stopping listening on: %v", addr)
		l.l.Close() // Usually redundant, but harmless.
		l.Done()
	}()
	for {
		conn, err := l.l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				l.log.Errorf("Critical accept failure: %v", err)
				return
			}
			continue
		}

		tcpConn := conn.(*net.TCPConn)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(keepAliveInterval)

		l.log.Debugf("Accepted new connection: %v", conn.RemoteAddr())

		l.onNewConn(conn)
	}

	// NOTREACHED
}

func (l *listener) onNewConn(conn net.Conn) {
	c := newIncomingConn(l, conn)

	l.closeAllWg.Add(1)
	l.Lock()
	defer func() {
		l.Unlock()
		go c.worker()
	}()
	c.e = l.conns.PushFront(c)
}

func (l *listener) onInitializedConn(c *incomingConn) {
	l.Lock()
	defer l.Unlock()

	c.isInitialized = true
}

func (l *listener) onClosedConn(c *incomingConn) {
	l.Lock()
	defer func() {
		l.Unlock()
		l.closeAllWg.Done()
	}()
	l.conns.Remove(c.e)
}

func (l *listener) isConnUnique(c *incomingConn) bool {
	l.Lock()
	defer l.Unlock()

	a := c.w.PeerCredentials()

	for e := l.conns.Front(); e != nil; e = e.Next() {
		cc := e.Value.(*incomingConn)

		// Skip checking a conn against itself, or against pre-handshake conns.
		if cc == c || cc.w == nil || !cc.isInitialized {
			continue
		}

		// Compare both by AdditionalData and PublicKey.
		b := cc.w.PeerCredentials()
		if bytes.Equal(a.AdditionalData, b.AdditionalData) {
			return false
		}
		if a.PublicKey.Equal(b.PublicKey) {
			return false
		}
	}

	return true
}

func newListener(s *Server, id int, addr string) (*listener, error) {
	var err error

	l := new(listener)
	l.s = s
	l.log = s.logBackend.GetLogger(fmt.Sprintf("listener:%d", id))
	l.conns = list.New()
	l.closeAllCh = make(chan interface{})
	l.Add(1)

	l.l, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	go l.worker()
	return l, nil
}
