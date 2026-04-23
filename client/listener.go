// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"net"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/client/transport"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
)

type listener struct {
	worker.Worker

	client *Client

	logBackend *log.Backend
	log        *logging.Logger

	listener transport.Listener

	connsLock *sync.RWMutex
	conns     map[[AppIDLength]byte]*incomingConn // appID -> *incomingConn

	// connOrder is the round-robin rotation order for the scheduler. It
	// mirrors the set of keys in conns; maintained under connsLock so the
	// scheduler can iterate deterministically. rrCursor advances through
	// this slice on every PickNextRequest call, hit or miss.
	connOrder [][AppIDLength]byte
	rrCursor  int

	// localDispatch, if set, is invoked by incoming_conn readers for
	// requests that need no mixnet I/O. Wired up by the daemon after
	// construction; tests that stand up a listener without a daemon leave
	// it nil, in which case the reader falls back to the scheduled path.
	localDispatch func(*Request)

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
	l.registerConn(c)
	l.connsLock.Unlock()

	status := l.getConnectionStatus()
	c.updateConnectionStatus(status)
	// Always send PKI doc event, even if empty - thin client expects it
	c.sendPKIDoc(docBlob)
}

func (l *listener) onClosedConn(c *incomingConn) {
	l.unregisterConn(*c.appID)

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
	for _, c := range l.conns {
		c.updateConnectionStatus(status)
	}
	l.connsLock.RUnlock()
}

func (l *listener) doUpdateFromPKIDoc(doc *cpki.Document) {
	docBlob, err := cbor.Marshal(doc)
	if err != nil {
		l.log.Errorf("cbor marshal failed: %s", err.Error())
		return
	}

	// A single conn in teardown (errConnClosed) must not abort the
	// broadcast to the other clients; log and continue.
	l.connsLock.RLock()
	for _, c := range l.conns {
		if err := c.sendPKIDoc(docBlob); err != nil {
			l.log.Warningf("sendPKIDoc to AppID %x failed: %s", c.appID[:], err)
		}
	}
	l.connsLock.RUnlock()

	l.decoySender.UpdateRates(ratesFromPKIDoc(doc))
}

// registerConn adds an incomingConn to the scheduler's rotation. The caller
// must hold connsLock.
func (l *listener) registerConn(c *incomingConn) {
	l.conns[*c.appID] = c
	l.connOrder = append(l.connOrder, *c.appID)
}

// unregisterConn removes an incomingConn from the scheduler's rotation,
// adjusting rrCursor so it keeps pointing at a live client. Callers close
// the conn's channels after this returns; holding connsLock for the delete
// guarantees the scheduler will not see a partially-dismantled conn.
func (l *listener) unregisterConn(appID [AppIDLength]byte) {
	l.connsLock.Lock()
	defer l.connsLock.Unlock()
	delete(l.conns, appID)
	for i, id := range l.connOrder {
		if id != appID {
			continue
		}
		l.connOrder = append(l.connOrder[:i], l.connOrder[i+1:]...)
		if l.rrCursor > i {
			l.rrCursor--
		}
		break
	}
	if n := len(l.connOrder); n == 0 {
		l.rrCursor = 0
	} else if l.rrCursor >= n {
		l.rrCursor %= n
	}
}

// PickNextRequest returns the next *Request to send, chosen by round-robin
// across connected thin clients. Each call advances the cursor past the
// visited client (whether a request was available or not) so a persistently
// busy client cannot re-win its own slot on consecutive calls. Returns nil
// when no connected client has a ready request — the sender falls back to
// a loop decoy in that case.
//
// Only an RLock is required: the scheduler is the sole RLock-tier writer
// of rrCursor (only one sender goroutine exists), and registerConn /
// unregisterConn / handleSessionToken take the full write lock, which
// excludes this path. Switching from Lock to RLock lets concurrent
// RLock readers — e.g. getConnection from the ingressWorker's reply path
// and PKI broadcast iterations — run without waiting on every Poisson tick.
func (l *listener) PickNextRequest() *Request {
	l.connsLock.RLock()
	defer l.connsLock.RUnlock()
	n := len(l.connOrder)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		idx := (l.rrCursor + i) % n
		c, ok := l.conns[l.connOrder[idx]]
		if !ok {
			continue
		}
		// Resends take priority over fresh requests within this client's
		// slot: they are already-promised work that the ARQ timer has
		// decided needs another attempt.
		select {
		case surbID, ok := <-c.resendCh:
			if !ok {
				// Closed channel: client is tearing down. The conn should
				// already be out of the map by the time its channels
				// close, but guard anyway.
				break
			}
			l.rrCursor = (idx + 1) % n
			return &Request{AppID: c.appID, ResendARQ: surbID}
		default:
		}
		select {
		case req, ok := <-c.requestCh:
			if !ok {
				break
			}
			l.rrCursor = (idx + 1) % n
			return req
		default:
		}
	}
	l.rrCursor = (l.rrCursor + 1) % n
	return nil
}

// SetLocalDispatch installs the handler invoked by incoming_conn readers
// for requests that do no mixnet I/O. Must be called before any thin
// clients connect. Safe to leave unset in tests that never exercise the
// real reader loop.
func (l *listener) SetLocalDispatch(fn func(*Request)) {
	l.localDispatch = fn
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
		for i, id := range l.connOrder {
			if id == oldAppID {
				l.connOrder[i] = *existingAppID
				break
			}
		}
		l.connsLock.Unlock()

		// Cancel any pending cleanup timer and flush queued replies
		l.disconnectedSessionsLock.Lock()
		if session, ok := l.disconnectedSessions[*existingAppID]; ok {
			session.CleanupTimer.Stop()
			for _, reply := range session.QueuedReplies {
				if err := c.sendResponse(reply); err != nil {
					l.log.Warningf("Dropped queued reply during session resume: %v", err)
				}
			}
			delete(l.disconnectedSessions, *existingAppID)
		}
		l.disconnectedSessionsLock.Unlock()

		token := st.ClientInstanceToken
		c.clientToken = &token
		l.log.Infof("Session resumed for token %x -> AppID %x", st.ClientInstanceToken[:4], existingAppID[:4])

		c.sendResponse(&Response{
			SessionTokenReply: &thin.SessionTokenReply{
				AppID:   existingAppID[:],
				Resumed: true,
			},
		})
		return
	}

	// New client: register token -> appID mapping
	token := st.ClientInstanceToken
	c.clientToken = &token
	l.clientTokens[st.ClientInstanceToken] = c.appID
	l.log.Infof("Session registered for token %x -> AppID %x", st.ClientInstanceToken[:4], c.appID[:4])

	c.sendResponse(&Response{
		SessionTokenReply: &thin.SessionTokenReply{
			AppID:   c.appID[:],
			Resumed: false,
		},
	})
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
// This uses writeResponse (direct socket write) rather than the channel-
// based sendResponse, because during shutdown the writer goroutine may
// have already exited and any queued response would never reach the socket.
func (l *listener) broadcastShutdownEvent() {
	l.connsLock.RLock()
	defer l.connsLock.RUnlock()
	for _, c := range l.conns {
		err := c.writeResponse(&Response{
			ShutdownEvent: &thin.ShutdownEvent{},
		})
		if err != nil {
			l.log.Debugf("Failed to send ShutdownEvent to client %x: %v", c.appID, err)
		}
	}
}

// New creates a new listener.
func NewListener(client *Client, rates *Rates, egressCh chan *Request, logBackend *log.Backend, onAppDisconnectFn func(*[AppIDLength]byte)) (*listener, error) {
	l := &listener{
		client:               client,
		logBackend:           logBackend,
		conns:                make(map[[AppIDLength]byte]*incomingConn),
		connsLock:            new(sync.RWMutex),
		updatePKIDocCh:       make(chan *cpki.Document, 2),
		updateStatusCh:       make(chan error, 2),
		onAppDisconnectFn:    onAppDisconnectFn,
		clientTokens:         make(map[[16]byte]*[AppIDLength]byte),
		disconnectedSessions: make(map[[AppIDLength]byte]*DisconnectedSession),
		sessionGracePeriod:   defaultSessionGracePeriod,
	}

	l.log = l.logBackend.GetLogger("client/listener")

	// Generate a random instance token to uniquely identify this daemon instance.
	_, err := rand.Reader.Read(l.instanceToken[:])
	if err != nil {
		return nil, err
	}

	l.decoySender = newSender(l.PickNextRequest, egressCh, client.cfg.Debug.DisableDecoyTraffic, logBackend)

	l.listener, err = client.cfg.Listen.Listen()
	if err != nil {
		return nil, err
	}

	l.Go(l.worker)
	l.Go(l.updatePKIDocWorker)
	l.Go(l.updateConnectionStatusWorker)
	return l, nil
}
