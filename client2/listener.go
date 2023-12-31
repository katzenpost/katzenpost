// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"io"
	"net"
	"sync"

	"github.com/charmbracelet/log"

	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
)

type listener struct {
	sync.Mutex
	worker.Worker

	client *Client

	log        *log.Logger
	logbackend io.Writer

	listener *net.UnixListener
	conns    map[uint64]*incomingConn // appID -> *incomingConn

	ingressCh   chan *Request
	decoySender *decoySender

	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup

	connectionStatusMutex sync.Mutex
	connectionStatus      error
}

func (l *listener) Halt() {
	l.decoySender.Halt()
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
	l.log.Debug("Listener worker begin")
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
	l.log.Debug("onNewConn begin")
	c := newIncomingConn(l, conn)

	l.closeAllWg.Add(1)
	l.Lock()
	defer func() {
		l.Unlock()
		go c.worker()
	}()
	l.conns[c.appID] = c

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

	doc.StripSignatures()
	l.log.Debug("send pki doc")
	c.sendPKIDoc(doc)
	l.log.Debug("onNewConn end")
}

func (l *listener) onClosedConn(c *incomingConn) {
	l.Lock()
	defer func() {
		l.Unlock()
		l.closeAllWg.Done()
	}()
	delete(l.conns, c.appID)
}

func (l *listener) getConnectionStatus() error {
	l.connectionStatusMutex.Lock()
	status := l.connectionStatus
	l.connectionStatusMutex.Unlock()
	return status
}

func (l *listener) updateConnectionStatus(status error) {

	l.connectionStatusMutex.Lock()
	l.connectionStatus = status
	l.connectionStatusMutex.Unlock()

	l.decoySender.UpdateConnectionStatus(status == nil)

	l.Lock()
	l.connectionStatusMutex.Lock()
	conns := l.conns
	l.connectionStatusMutex.Unlock()

	for key, _ := range conns {
		l.conns[key].updateConnectionStatus(status)
	}
	l.Unlock()

}

func (l *listener) updateRatesFromPKIDoc(doc *cpki.Document) {
	l.decoySender.UpdateRates(ratesFromPKIDoc(doc))
}

func (l *listener) getConnection(appID uint64) *incomingConn {
	l.Lock()
	defer l.Unlock()

	conn, ok := l.conns[appID]
	if !ok {
		return nil
	}
	return conn
}

// New creates a new listener.
func NewListener(client *Client, rates *Rates, egressCh chan *Request, logbackend io.Writer) (*listener, error) {
	var err error

	l := &listener{
		client: client,
		log: log.NewWithOptions(logbackend, log.Options{
			Prefix: "listener",
			Level:  log.DebugLevel,
		}),
		logbackend: logbackend,
		conns:      make(map[uint64]*incomingConn),
		closeAllCh: make(chan interface{}),
		ingressCh:  make(chan *Request),
	}

	l.decoySender = newDecoySender(rates, l.ingressCh, egressCh)

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
