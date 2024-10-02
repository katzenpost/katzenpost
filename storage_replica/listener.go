// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"container/list"
	"crypto/hmac"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem/schemes"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/http/common"
)

type listener struct {
	sync.Mutex
	worker.Worker

	log *logging.Logger

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
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				l.log.Errorf("accept failure: %v", err)
				return
			}
			continue
		}

		tcpConn, ok := conn.(*net.TCPConn)
		if ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(constants.KeepAliveInterval)
		}

		l.log.Debugf("Accepted new connection: %v", conn.RemoteAddr())

		l.onNewConn(conn)
	}

	// NOTREACHED
}

func (l *listener) onNewConn(conn net.Conn) {
	scheme := schemes.ByName(l.glue.Config().Server.WireKEM)
	if scheme == nil {
		panic("KEM scheme not found in registry")
	}
	pkiScheme := signSchemes.ByName(l.glue.Config().Server.PKISignatureScheme)
	if pkiScheme == nil {
		panic("PKI signature scheme not found in registry")
	}
	c := newIncomingConn(l, conn, l.glue.Config().SphinxGeometry, scheme, pkiScheme)

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
			ql, err := quic.ListenAddr(u.Host, common.GenerateTLSConfig(), nil)
			if err != nil {
				l.log.Errorf("Failed to start listener '%v': %v", addr, err)
				return nil, err
			}
			// Wrap quic.Listener with common.QuicListener
			// so it implements like net.Listener for a
			// single QUIC Stream
			l.l = &common.QuicListener{Listener: ql}
		default:
			return nil, fmt.Errorf("Unsupported listener scheme '%v': %v", addr, err)
		}
	}

	l.Go(l.worker)
	return l, nil
}
