// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
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

	// instanceToken is a random token that uniquely identifies this daemon instance.
	// Thin clients use it to detect same-instance reconnects vs new-instance reconnects.
	instanceToken [16]byte

	// Callback function to clean up state when a connection closes
	onAppDisconnectFn func(*[AppIDLength]byte)

	clientTokens     map[[16]byte]*[AppIDLength]byte
	clientTokensLock sync.Mutex

	disconnectedSessions     map[[AppIDLength]byte]*DisconnectedSession
	disconnectedSessionsLock sync.Mutex

	sessionGracePeriod time.Duration
}

func (l *listener) Shutdown() {
	shutdownStart := time.Now()
	l.log.Debug("Starting listener shutdown")

	// Close the listener, wait for worker() to return.
	l.listener.Close()

	// Parallelize listener and decoy sender shutdown for faster cleanup
	var shutdownWg sync.WaitGroup
	shutdownWg.Add(2)

	go func() {
		defer shutdownWg.Done()
		start := time.Now()
		l.log.Debug("Stopping listener worker")
		// stop listener, and stop Accepting connections
		l.Halt()
		l.log.Debugf("Listener worker stopped in %v", time.Since(start))
	}()

	go func() {
		defer shutdownWg.Done()
		start := time.Now()
		l.log.Debug("Stopping decoy sender")
		// stop the decoy Sender
		l.decoySender.Halt()
		l.log.Debugf("Decoy sender stopped in %v", time.Since(start))
	}()

	shutdownWg.Wait()
	l.log.Debugf("Listener shutdown complete in %v", time.Since(shutdownStart))
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
	// Get document if available (don't block or reject if not ready)
	var docBlob []byte
	l.client.RLock()
	pki := l.client.pki
	l.client.RUnlock()
	if pki != nil {
		docBlob, _ = pki.currentDocument()
	}

	c := newIncomingConn(l, conn)

	defer func() {
		c.start()
	}()

	l.connsLock.Lock()
	l.conns[*c.appID] = c
	l.connsLock.Unlock()

	status := l.getConnectionStatus()
	c.updateConnectionStatus(status)
	// Always send PKI doc event, even if empty - thin client expects it
	c.sendPKIDoc(docBlob)
}

func (l *listener) onClosedConn(c *incomingConn) {
	l.connsLock.Lock()
	delete(l.conns, *c.appID)
	l.connsLock.Unlock()

	if c.explicitClose {
		// ThinClose received: destroy all state immediately
		if l.onAppDisconnectFn != nil {
			l.onAppDisconnectFn(c.appID)
		}
		if c.clientToken != nil {
			l.clientTokensLock.Lock()
			delete(l.clientTokens, *c.clientToken)
			l.clientTokensLock.Unlock()
		}
		return
	}

	if c.clientToken != nil {
		// Unintentional disconnect from session-aware client: preserve state
		appID := c.appID
		token := *c.clientToken
		l.disconnectedSessionsLock.Lock()
		session := &DisconnectedSession{
			AppID:        appID,
			Token:        token,
			DisconnectAt: time.Now(),
		}
		session.CleanupTimer = time.AfterFunc(l.sessionGracePeriod, func() {
			l.disconnectedSessionsLock.Lock()
			_, stillDisconnected := l.disconnectedSessions[*appID]
			if !stillDisconnected {
				l.disconnectedSessionsLock.Unlock()
				return
			}
			delete(l.disconnectedSessions, *appID)
			l.disconnectedSessionsLock.Unlock()

			l.log.Infof("Grace period expired for session %x, cleaning up", appID[:4])

			l.clientTokensLock.Lock()
			delete(l.clientTokens, token)
			l.clientTokensLock.Unlock()

			if l.onAppDisconnectFn != nil {
				l.onAppDisconnectFn(appID)
			}
		})
		l.disconnectedSessions[*appID] = session
		l.disconnectedSessionsLock.Unlock()
		l.log.Infof("Preserving state for disconnected session %x (grace period %v)", appID[:4], l.sessionGracePeriod)
		return
	}

	// Legacy client (no token): clean up immediately as before
	if l.onAppDisconnectFn != nil {
		l.onAppDisconnectFn(c.appID)
	}
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

const (
	defaultSessionGracePeriod = 30 * time.Minute
	maxQueuedReplies          = 1000
)

type DisconnectedSession struct {
	AppID         *[AppIDLength]byte
	Token         [16]byte
	DisconnectAt  time.Time
	CleanupTimer  *time.Timer
	QueuedReplies []*Response
}

// handleSessionToken processes a SessionToken request from a thin client.
// If the token was previously registered, the connection resumes the old app ID.
// Otherwise a new token->appID mapping is created.
func (l *listener) handleSessionToken(c *incomingConn, st *thin.SessionToken) {
	l.clientTokensLock.Lock()
	defer l.clientTokensLock.Unlock()

	existingAppID, found := l.clientTokens[st.ClientInstanceToken]
	if found {
		oldAppID := *c.appID

		l.connsLock.Lock()
		delete(l.conns, oldAppID)
		c.appID = existingAppID
		l.conns[*existingAppID] = c
		l.connsLock.Unlock()

		// Cancel any pending cleanup timer and flush queued replies
		l.disconnectedSessionsLock.Lock()
		if session, ok := l.disconnectedSessions[*existingAppID]; ok {
			session.CleanupTimer.Stop()
			for _, reply := range session.QueuedReplies {
				select {
				case c.sendToClientCh <- reply:
				default:
					l.log.Warningf("Dropped queued reply during session resume (channel full)")
				}
			}
			delete(l.disconnectedSessions, *existingAppID)
		}
		l.disconnectedSessionsLock.Unlock()

		token := st.ClientInstanceToken
		c.clientToken = &token
		l.log.Infof("Session resumed for token %x -> AppID %x", st.ClientInstanceToken[:4], existingAppID[:4])

		select {
		case c.sendToClientCh <- &Response{
			SessionTokenReply: &thin.SessionTokenReply{
				AppID:   existingAppID[:],
				Resumed: true,
			},
		}:
		case <-l.HaltCh():
		}
		return
	}

	// New client: register token -> appID mapping
	token := st.ClientInstanceToken
	c.clientToken = &token
	l.clientTokens[st.ClientInstanceToken] = c.appID
	l.log.Infof("Session registered for token %x -> AppID %x", st.ClientInstanceToken[:4], c.appID[:4])

	select {
	case c.sendToClientCh <- &Response{
		SessionTokenReply: &thin.SessionTokenReply{
			AppID:   c.appID[:],
			Resumed: false,
		},
	}:
	case <-l.HaltCh():
	}
}

// queueReplyForDisconnected buffers a reply for a disconnected session.
// Returns true if the reply was queued, false if no disconnected session exists.
func (l *listener) queueReplyForDisconnected(appID *[AppIDLength]byte, reply *Response) bool {
	l.disconnectedSessionsLock.Lock()
	defer l.disconnectedSessionsLock.Unlock()

	session, ok := l.disconnectedSessions[*appID]
	if !ok {
		return false
	}
	if len(session.QueuedReplies) >= maxQueuedReplies {
		l.log.Warningf("Dropped reply for disconnected session %x (queue full)", appID[:4])
		return true
	}
	session.QueuedReplies = append(session.QueuedReplies, reply)
	return true
}

// broadcastShutdownEvent sends a ShutdownEvent to all connected thin clients.
// This uses direct socket writes rather than the channel-based sendToClientCh,
// because during shutdown the writer goroutine may have already exited.
func (l *listener) broadcastShutdownEvent() {
	l.connsLock.RLock()
	defer l.connsLock.RUnlock()
	for _, c := range l.conns {
		err := c.sendResponse(&Response{
			ShutdownEvent: &thin.ShutdownEvent{},
		})
		if err != nil {
			l.log.Debugf("Failed to send ShutdownEvent to client %x: %v", c.appID, err)
		}
	}
}

// New creates a new listener.
func NewListener(client *Client, rates *Rates, egressCh chan *Request, logBackend *log.Backend, onAppDisconnectFn func(*[AppIDLength]byte)) (*listener, error) {
	ingressSize := 200
	l := &listener{
		client:               client,
		logBackend:           logBackend,
		conns:                make(map[[AppIDLength]byte]*incomingConn),
		connsLock:            new(sync.RWMutex),
		ingressCh:            make(chan *Request, ingressSize),
		updatePKIDocCh:       make(chan *cpki.Document, 2),
		updateStatusCh:       make(chan error, 2),
		onAppDisconnectFn:    onAppDisconnectFn,
		clientTokens:         make(map[[16]byte]*[AppIDLength]byte),
		disconnectedSessions: make(map[[AppIDLength]byte]*DisconnectedSession),
		sessionGracePeriod:   defaultSessionGracePeriod,
	}

	l.log = l.logBackend.GetLogger("client2/listener")

	// Generate a random instance token to uniquely identify this daemon instance.
	_, err := rand.Reader.Read(l.instanceToken[:])
	if err != nil {
		return nil, err
	}

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
		unixAddr, err := net.ResolveUnixAddr(network, address)
		if err != nil {
			return nil, err
		}
		l.listener, err = net.ListenUnix(network, unixAddr)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("incorrect network type")
	}

	l.Go(l.worker)
	l.Go(l.updatePKIDocWorker)
	l.Go(l.updateConnectionStatusWorker)
	return l, nil
}
