// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"net"
	"sync"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
	"gopkg.in/op/go-logging.v1"
)

type listener struct {
	worker.Worker

	client *Client

	logBackend *log.Backend
	log        *logging.Logger

	listener net.Listener

	connsLock *sync.RWMutex
	conns     map[[AppIDLength]byte]*incomingConn // appID -> *incomingConn

	ingressCh   chan *Request
	decoySender *sender

	connectionStatusMutex sync.Mutex
	connectionStatus      error

	updatePKIDocCh chan *cpki.Document
	updateStatusCh chan error
}

func (l *listener) Shutdown() {
	// Close the listener, wait for worker() to return.
	l.listener.Close()
	// stop listener, and stop Accepting connections
	l.Halt()
	// stop the decoy Sender
	l.decoySender.Halt()
}

func (l *listener) updateFromPKIDoc(doc *cpki.Document) {
	select {
	case <-l.HaltCh():
		return
	case l.updatePKIDocCh <- doc:
	}
}

func (l *listener) updatePKIDocWorker() {
	for {
		select {
		case <-l.HaltCh():
			return
		case doc := <-l.updatePKIDocCh:
			l.doUpdateFromPKIDoc(doc)
		}
	}
}

func (l *listener) worker() {
	l.log.Debug("Listener worker begin")
	addr := l.listener.Addr()
	l.log.Infof("Listening on: %v", addr)
	defer func() {
		l.log.Infof("Stopping listening on: %v", addr)
		l.listener.Close() // Usually redundant, but harmless.
	}()
	for {
		select {
		case <-l.HaltCh():
			return
		default:
		}
		conn, err := l.listener.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				l.log.Errorf("Critical accept failure: %v", err)
				return
			}
			continue
		}
		l.log.Debugf("Accepted new connection: %v", conn.RemoteAddr())
		l.onNewConn(conn)
	}
	// NOTREACHED
}

func (l *listener) onNewConn(conn net.Conn) {
	l.log.Debug("onNewConn begin")
	// make sure we can serve a document before anything else
	docBlob, doc := l.client.CurrentDocument()
	if doc == nil {
		l.log.Error("no pki document to serve")
		return
	}

	c := newIncomingConn(l, conn)

	defer func() {
		c.start()
	}()

	l.connsLock.Lock()
	l.conns[*c.appID] = c
	l.connsLock.Unlock()

	l.log.Debug("get connection status")
	status := l.getConnectionStatus()
	l.log.Debug("send connection status")
	c.updateConnectionStatus(status)
	l.log.Debug("getting current pki doc")

	l.log.Debug("send pki doc")
	c.sendPKIDoc(docBlob)

	l.log.Debug("onNewConn end")
}

func (l *listener) onClosedConn(c *incomingConn) {
	l.connsLock.Lock()
	delete(l.conns, *c.appID)
	l.connsLock.Unlock()
}

func (l *listener) getConnectionStatus() error {
	l.connectionStatusMutex.Lock()
	status := l.connectionStatus
	l.connectionStatusMutex.Unlock()
	return status
}

func (l *listener) updateConnectionStatusWorker() {
	for {
		select {
		case <-l.HaltCh():
			return
		case status := <-l.updateStatusCh:
			l.doUpdateConnectionStatus(status)
		}
	}
}

func (l *listener) updateConnectionStatus(status error) {
	select {
	case <-l.HaltCh():
		return
	case l.updateStatusCh <- status:
	}
}

func (l *listener) doUpdateConnectionStatus(status error) {

	l.connectionStatusMutex.Lock()
	l.connectionStatus = status
	l.connectionStatusMutex.Unlock()

	l.decoySender.UpdateConnectionStatus(status == nil)

	l.connsLock.RLock()
	conns := l.conns

	for key, _ := range conns {
		l.conns[key].updateConnectionStatus(status)
	}
	l.connsLock.RUnlock()
}

func (l *listener) doUpdateFromPKIDoc(doc *cpki.Document) {
	// send doc to all thin clients
	docBlob, err := cbor.Marshal(doc)
	if err != nil {
		l.log.Errorf("cbor marshal failed: %s", err.Error())
		return
	}

	l.connsLock.RLock()
	conns := l.conns
	for key, _ := range conns {
		err = l.conns[key].sendPKIDoc(docBlob)
		if err != nil {
			l.log.Errorf("sendPKIDoc failure: %s", err)
			return
		}
	}
	l.connsLock.RUnlock()

	// update our send rates from PKI doc
	l.decoySender.UpdateRates(ratesFromPKIDoc(doc))
}

func (l *listener) getConnection(appID *[AppIDLength]byte) *incomingConn {
	l.connsLock.RLock()
	conn, ok := l.conns[*appID]
	l.connsLock.RUnlock()
	if !ok {
		return nil
	}
	return conn
}

// New creates a new listener.
func NewListener(client *Client, rates *Rates, egressCh chan *Request, logBackend *log.Backend) (*listener, error) {
	ingressSize := 200
	l := &listener{
		client:         client,
		logBackend:     logBackend,
		conns:          make(map[[AppIDLength]byte]*incomingConn),
		connsLock:      new(sync.RWMutex),
		ingressCh:      make(chan *Request, ingressSize),
		updatePKIDocCh: make(chan *cpki.Document, 2),
		updateStatusCh: make(chan error, 2),
	}

	l.log = l.logBackend.GetLogger("client2/listener")

	l.decoySender = newSender(l.ingressCh, egressCh, client.cfg.Debug.DisableDecoyTraffic, logBackend)

	network := client.cfg.ListenNetwork
	address := client.cfg.ListenAddress

	switch network {
	case "tcp6":
		fallthrough
	case "tcp4":
		fallthrough
	case "tcp":
		tcpAddr, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			return nil, err
		}
		l.listener, err = net.ListenTCP(network, tcpAddr)
		if err != nil {
			return nil, err
		}
	case "unix":
		fallthrough
	case "unixgram":
		fallthrough
	case "unixpacket":
		unixAddr, err := net.ResolveUnixAddr(network, address)
		if err != nil {
			return nil, err
		}
		l.listener, err = net.ListenUnix(network, unixAddr)
		if err != nil {
			return nil, err
		}
	}

	l.Go(l.worker)
	l.Go(l.updatePKIDocWorker)
	l.Go(l.updateConnectionStatusWorker)
	return l, nil
}
