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
package incoming

import (
	"container/list"
	"crypto/hmac"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
	kquic "github.com/katzenpost/katzenpost/quic"
	"github.com/katzenpost/katzenpost/server/internal/constants"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	quic "github.com/quic-go/quic-go"
	"gopkg.in/op/go-logging.v1"
)

type listener struct {
	sync.Mutex
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	l     net.Listener
	conns *list.List

	incomingCh chan<- interface{}
	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup

	sendRatePerMinute uint64
	sendBurst         uint64
}

func (l *listener) Halt() {
	// Close the listener, wait for worker() to return.
	l.l.Close()
	l.Worker.Halt()

	// Close all connections belonging to the listener.
	//
	// Note: Worst case this can take up to the handshake timeout to
	// actually complete, since the channel isn't checked mid-handshake.
	close(l.closeAllCh)
	l.closeAllWg.Wait()
}

func (l *listener) OnNewSendRatePerMinute(sendRatePerMinute uint64) {
	atomic.StoreUint64(&l.sendRatePerMinute, sendRatePerMinute)
}

func (l *listener) OnNewSendBurst(sendBurst uint64) {
	atomic.StoreUint64(&l.sendBurst, sendBurst)
}

func (l *listener) worker() {
	addr := l.l.Addr()
	l.log.Noticef("Listening on: %v", addr)
	defer func() {
		l.log.Noticef("Stopping listening on: %v", addr)
		l.l.Close() // Usually redundant, but harmless.
	}()
	for {
		select {
		case <-l.closeAllCh:
			return
		default:
		}
		conn, err := l.l.Accept()
		switch e := err.(type) {
		case nil:
			// No Error
		case net.Error:
			if !e.Timeout() && !e.Temporary() {
				l.log.Errorf("accept failure: %v", err)
				return
			}
			continue
		default:
			l.log.Errorf("accept failure: %v", err)
			return
		}

		switch conn := conn.(type) {
		case *net.TCPConn:
			l.log.Debugf("Accepted new tcp connection: %v", conn.RemoteAddr())
			conn.SetKeepAlive(true)
			l.log.Debugf("SetKeepAlive(true)")
			conn.SetKeepAlivePeriod(constants.KeepAliveInterval)
			l.log.Debugf("SetKeepAlivePeriod(%d)", constants.KeepAliveInterval)
		case *kquic.QuicConn:
			l.log.Debugf("Accepted new quic connection: %v", conn.RemoteAddr())
		default:
			panic("Unsupported Connection Type")
		}

		l.onNewConn(conn)
	}

	// NOTREACHED
}

func (l *listener) onNewConn(conn net.Conn) {
	c := newIncomingConn(l, conn, l.glue.Config().SphinxGeometry)

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

// GetConnIdentities returns a slice of byte slices each corresponding
// to a currently connected client identity.
func (l *listener) GetConnIdentities() (map[[sConstants.RecipientIDLength]byte]interface{}, error) {
	l.Lock()
	defer l.Unlock()

	identitySet := make(map[[sConstants.RecipientIDLength]byte]interface{})
	for e := l.conns.Front(); e != nil; e = e.Next() {
		cc := e.Value.(*incomingConn)

		// Skip checking against pre-handshake conns.
		if cc.w == nil || !cc.isInitialized {
			continue
		}

		b, err := cc.w.PeerCredentials()
		if err != nil {
			l.log.Errorf("Session fail: %s", err)
			return nil, errors.New("strange failure to retrieve session identity")
		}
		key := [sConstants.RecipientIDLength]byte{}
		copy(key[:], b.AdditionalData)
		identitySet[key] = struct{}{}
	}
	return identitySet, nil
}

func (l *listener) CloseOldConns(ptr interface{}) error {
	c := ptr.(*incomingConn)

	l.Lock()
	defer l.Unlock()

	a, err := c.w.PeerCredentials()
	if err != nil {
		l.log.Errorf("Session fail: %s", err)
		return err
	}

	for e := l.conns.Front(); e != nil; e = e.Next() {
		cc := e.Value.(*incomingConn)

		// Skip checking a conn against itself, or against pre-handshake conns.
		if cc == c || cc.w == nil || !cc.isInitialized {
			continue
		}

		// Compare both by AdditionalData and PublicKey.
		b, err := cc.w.PeerCredentials()
		if err != nil {
			continue
		}

		if !hmac.Equal(a.AdditionalData, b.AdditionalData) {
			continue
		}
		if !a.PublicKey.Equal(b.PublicKey) {
			continue
		}
		cc.Close()
	}

	return nil
}

// New creates a new listener.
func New(glue glue.Glue, incomingCh chan<- interface{}, id int, addr string) (glue.Listener, error) {
	var err error

	l := &listener{
		glue:       glue,
		log:        glue.LogBackend().GetLogger(fmt.Sprintf("listener:%d", id)),
		conns:      list.New(),
		incomingCh: incomingCh,
		closeAllCh: make(chan interface{}),
	}

	// parse the Address line as a URL
	u, err := url.Parse(addr)
	if err == nil {
		switch u.Scheme {
		case "tcp", "tcp4", "tcp6":
			l.l, err = net.Listen(u.Scheme, u.Host)
			if err != nil {
				l.log.Errorf("Failed to start listener '%v': %v", addr, err)
				return nil, err
			}
		case "quic":
			ql, err := quic.ListenAddr(u.Host, kquic.GenerateTLSConfig(), nil)
			if err != nil {
				l.log.Errorf("Failed to start listener '%v': %v", addr, err)
				return nil, err
			}
			// Wrap quic.Listener with kquic.QuicListener
			// so it implements like net.Listener for a
			// single QUIC Stream
			l.l = &kquic.QuicListener{Listener: ql}
		default:
			return nil, fmt.Errorf("Unsupported listener scheme '%v': %v", addr, err)
		}
	}

	l.Go(l.worker)
	return l, nil
}
