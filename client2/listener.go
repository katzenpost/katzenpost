// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"net"
	"sync"

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

	listener *net.UnixListener

	connsLock *sync.RWMutex
	conns     map[[AppIDLength]byte]*incomingConn // appID -> *incomingConn

	ingressCh   chan *Request
	decoySender *sender

	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup

	connectionStatusMutex sync.Mutex
	connectionStatus      error

	updatePKIDocCh chan *cpki.Document
	updateStatusCh chan error
}

func (l *listener) Halt() {
	l.decoySender.Halt()
	l.decoySender.Wait()
	// Close the listener, wait for worker() to return.
	l.listener.Close()
	l.Worker.Halt()
	l.Worker.Wait()
	// Close all connections belonging to the listener.
	//
	// Note: Worst case this can take up to the handshake timeout to
	// actually complete, since the channel isn't checked mid-handshake.
	close(l.closeAllCh)
	l.closeAllWg.Wait()
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
		l.onNewConn(conn.(*net.UnixConn))
	}
	// NOTREACHED
}

func (l *listener) onNewConn(conn *net.UnixConn) {
	l.log.Debug("onNewConn begin")
	c := newIncomingConn(l, conn)

	l.closeAllWg.Add(1)

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

	l.client.WaitForCurrentDocument()
	doc := l.client.CurrentDocument()
	if doc == nil {
		panic("doc is nil")
	}

	l.log.Debug("send pki doc")
	mydoc := doc
	docBlob, err := mydoc.MarshalBinary()
	if err != nil {
		l.log.Errorf("cbor fail: %s", err)
	}
	c.sendPKIDoc(docBlob)
	l.log.Debug("onNewConn end")
}

func (l *listener) onClosedConn(c *incomingConn) {
	l.connsLock.Lock()
	delete(l.conns, *c.appID)
	l.connsLock.Unlock()
	l.closeAllWg.Done()
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

	mydoc := doc
	docBlob, err := mydoc.MarshalBinary()
	if err != nil {
		l.log.Errorf("cbor marshal failed: %s", err.Error())
		return
	}

	l.connsLock.RLock()
	conns := l.conns
	defer l.connsLock.RUnlock()
	for key, _ := range conns {
		err = l.conns[key].sendPKIDoc(docBlob)
		if err != nil {
			l.log.Errorf("sendPKIDoc failure: %s", err)
			return
		}
	}

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
		closeAllCh:     make(chan interface{}),
		ingressCh:      make(chan *Request, ingressSize),
		updatePKIDocCh: make(chan *cpki.Document, 2),
		updateStatusCh: make(chan error, 2),
	}

	l.log = l.logBackend.GetLogger("client2/listener")

	l.decoySender = newSender(l.ingressCh, egressCh, client.cfg.Debug.DisableDecoyTraffic, logBackend)

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
	l.Go(l.updatePKIDocWorker)
	l.Go(l.updateConnectionStatusWorker)
	return l, nil
}
