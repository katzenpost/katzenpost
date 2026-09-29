// SPDX-FileCopyrightText: Copyright (C) 2017 Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"crypto/hmac"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/wire/handshakeinstrument"
	httpCommon "github.com/katzenpost/katzenpost/quic/common"
	"github.com/katzenpost/katzenpost/replica/instrument"
)

var outgoingConnID uint64

// reauthGraceLimit is how many consecutive reauthentication failures a
// live session survives before being torn down. Descriptor churn during
// staggered upgrades and dirauth wobble transiently drops a healthy peer
// from the newest document; the peer was authenticated at handshake, so
// severing on the first miss orphans in-flight work for no gain.
const reauthGraceLimit = 3

// reauthOutcome folds one reauthentication result into the consecutive
// failure counter and reports whether the session should stay up.
func (c *outgoingConn) reauthOutcome(valid bool) bool {
	if valid {
		c.reauthFailures = 0
		return true
	}
	c.reauthFailures++
	if c.reauthFailures >= reauthGraceLimit {
		c.log.Warningf("Disconnecting %s, peer reauthentication failed %d consecutive times.", c.dst.Name, c.reauthFailures)
		return false
	}
	c.log.Warningf("Peer %s reauthentication failed (%d/%d), keeping session.", c.dst.Name, c.reauthFailures, reauthGraceLimit)
	return true
}

type outgoingConn struct {
	scheme kem.Scheme
	geo    *geo.Geometry
	co     GenericConnector
	log    *logging.Logger

	dst *cpki.ReplicaDescriptor
	ch  chan commands.Command

	// unknownCmdSeen dedups unhandled-command warnings per type.
	// Touched only by the connection-event-loop goroutine.
	unknownCmdSeen map[string]bool

	// reauthFailures counts consecutive reauthentication failures.
	// Touched only by the connection worker goroutine.
	reauthFailures int

	id          uint64
	retryDelay  time.Duration
	egressErrCh chan struct{}

	// sessionUp reports whether a handshaked session is currently
	// carrying this peer's queue. False before the first handshake and
	// between sessions, including while the worker is redialling a peer
	// that is down. Read by dispatching goroutines, written only by the
	// connection worker.
	sessionUp atomic.Bool
}

func (c *outgoingConn) IsPeerValid(creds *wire.PeerCredentials) bool {
	if !c.validateIdentityHash(creds) {
		return false
	}
	if !c.validateLinkKey(creds) {
		return false
	}
	if !c.validateReplicaInPKI(creds) {
		return false
	}
	c.log.Debug("OutgoingConn: Authentication successful")
	return true
}

// validateIdentityHash verifies the identity hash matches what we expect
func (c *outgoingConn) validateIdentityHash(creds *wire.PeerCredentials) bool {
	idHash := hash.Sum256(c.dst.IdentityKey)
	if !hmac.Equal(idHash[:], creds.AdditionalData) {
		c.log.Debug("OutgoingConn: Identity hash mismatch")
		return false
	}
	return true
}

// validateLinkKey verifies the link key matches what we expect
func (c *outgoingConn) validateLinkKey(creds *wire.PeerCredentials) bool {
	keyblob, err := creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if !hmac.Equal(c.dst.LinkKey, keyblob) {
		c.log.Debug("OutgoingConn: Link key mismatch")
		return false
	}
	return true
}

// validateReplicaInPKI verifies the replica is in the current PKI
// document, or in a cached document for the previous or next epoch
// (grace for late dirauth publication and staggered-upgrade churn).
func (c *outgoingConn) validateReplicaInPKI(creds *wire.PeerCredentials) bool {
	var nodeID [sConstants.NodeIDLength]byte
	copy(nodeID[:], creds.AdditionalData)
	if _, isReplica := c.co.Server().PKIWorker.replicas.GetReplicaDescriptor(&nodeID); isReplica {
		return true
	}
	if descs := c.co.Server().PKIWorker.replicaDescriptorsForAuth(&nodeID); len(descs) > 0 {
		c.log.Noticef("OutgoingConn: authenticated %s via cached-document grace window", descs[0].Name)
		return true
	}
	c.log.Debug("OutgoingConn: PKI authentication failed - replica not found")
	return false
}

func (c *outgoingConn) dispatchCommand(cmd commands.Command) {
	// A peer with no live session has nothing to carry a proxy request.
	// The per-peer queue would hold it until a session comes up, which
	// for a peer that is down is not within the waiter's share of the
	// sweep budget: the connection is only reported dead by FailPeer
	// when an established session ends, and one that never handshakes
	// never arms that. So the sweep would sit out its whole share
	// against a peer known to be refusing connections before trying the
	// co-holder, which is the failover this queue silently defers.
	//
	// Replication writes are the opposite case and fall through: they
	// have no waiter, and the queue is exactly where they should wait
	// for the peer to come back.
	if !c.sessionUp.Load() && failUndeliverableProxyRequest(c.co, c.log, cmd) {
		c.log.Warningf("No session with %s, failing proxy request %T", c.dst.Name, cmd)
		return
	}

	select {
	case c.ch <- cmd:
		instrument.OutgoingQueueLength(c.dst.Name, len(c.ch))
	case <-c.co.CloseAllCh():
	default:
		// A full per-peer queue means the peer is not draining. Never
		// block the dispatching goroutine on it (proxy handlers
		// dispatch before arming their own timeout); fail the proxy
		// request so its sweep fails over now, or park a replication
		// write in the connector retry queue.
		if failUndeliverableProxyRequest(c.co, c.log, cmd) {
			c.log.Warningf("Outgoing queue for %s full, failing proxy request %T", c.dst.Name, cmd)
			return
		}
		idHash := hash.Sum256(c.dst.IdentityKey)
		c.log.Warningf("Outgoing queue for %s full, queueing %T for retry", c.dst.Name, cmd)
		c.co.QueueForRetry(cmd, idHash)
	}
}

func (c *outgoingConn) worker() {
	retryIncrement := epochtime.Period / 64
	maxRetryDelay := epochtime.Period / 8

	defer func() {
		c.log.Debugf("Halting connect worker.")
		// Drain pending commands into the retry queue so nothing is
		// lost with the conn. c.ch is deliberately never closed:
		// OnClosedConn removes the conn from the connector map, but a
		// concurrent dispatcher may still hold the old pointer, and a
		// send on a closed channel panics where a send on an abandoned
		// one merely takes the dispatch fallback.
		c.drainToRetryQueue()
		c.co.OnClosedConn(c)
	}()

	dialCtx, cancelFn, dialer, dialCheckCreds := c.initializeConnection()
	defer cancelFn()

	// Establish the outgoing connection.
	for {
		if !c.validatePKIAndUpdateCredentials(&dialCheckCreds) {
			return
		}

		dstAddrs := c.getDestinationAddresses()
		if len(dstAddrs) == 0 {
			c.log.Warningf("Bailing out of Dial loop, no suitable addresses found.")
			return
		}

		if c.attemptConnectionToAddresses(dstAddrs, dialCtx, dialer, retryIncrement, maxRetryDelay) {
			return // Connection was canceled or we should exit
		}
	}
}

// getDestinationAddresses flattens the lists of addresses to dial to
func (c *outgoingConn) getDestinationAddresses() []string {
	var dstAddrs []string
	for _, t := range cpki.ClientTransports {
		if v, ok := c.dst.Addresses[t]; ok {
			dstAddrs = append(dstAddrs, v...)
		}
	}
	return dstAddrs
}

// drainToRetryQueue moves any commands parked in the per-peer FIFO into
// the connector retry queue, whose TTL and dedup bound their staleness.
// Called between failed session attempts: while no session is up nothing
// else drains the FIFO, and a command must not sit there unbounded.
func (c *outgoingConn) drainToRetryQueue() {
	idHash := hash.Sum256(c.dst.IdentityKey)
	drained := 0
	for {
		select {
		case cmd := <-c.ch:
			if _, isProxyRequest := cmd.(*commands.ReplicaMessage); isProxyRequest {
				// FailPeer already failed every pending proxy request
				// to this peer when the session died, so this one has
				// no waiter left to deliver to.
				continue
			}
			c.co.QueueForRetry(cmd, idHash)
			drained++
		default:
			if drained > 0 {
				c.log.Debugf("Queued %d parked commands for retry while disconnected", drained)
			}
			return
		}
	}
}

// attemptConnectionToAddresses tries to connect to each address with retry logic
func (c *outgoingConn) attemptConnectionToAddresses(dstAddrs []string, dialCtx context.Context, dialer net.Dialer, retryIncrement, maxRetryDelay time.Duration) bool {
	for _, addr := range dstAddrs {
		c.drainToRetryQueue()
		select {
		case <-time.After(common.JitterDelay(c.retryDelay)):
			// Back off incrementally on reconnects.
			//
			// This maybe should be tracked per address, but whatever. I
			// remember when IPng was supposed to take over the world in
			// the 90s, and it still hasn't happened yet.
			c.retryDelay += retryIncrement
			if c.retryDelay > maxRetryDelay {
				c.retryDelay = maxRetryDelay
			}
		case <-dialCtx.Done():
			// Canceled mid-retry delay.
			c.log.Debugf("(Re)connection attempts canceled.")
			return true
		}

		if c.dialAndHandleConnection(addr, dialCtx, dialer, retryIncrement, maxRetryDelay) {
			return true // Connection was canceled or we should exit
		}
	}
	return false
}

// dialAndHandleConnection handles dialing to a single address and managing the connection
func (c *outgoingConn) dialAndHandleConnection(addr string, dialCtx context.Context, dialer net.Dialer, retryIncrement, maxRetryDelay time.Duration) bool {
	// Dial.
	u, err := url.Parse(addr)
	if err != nil {
		c.log.Warningf("Failed to parse addr: %v", err)
		return false
	}
	c.log.Debugf("Dialing: %v", u.Host)

	conn, err := httpCommon.DialURL(u, dialCtx, dialer.DialContext)
	select {
	case <-dialCtx.Done():
		// Canceled.
		if conn != nil {
			conn.Close()
		}
		return true
	default:
		if err != nil {
			c.log.Warningf("Failed to connect to '%v': %v", u.Host, err)
			return false
		}
	}
	c.log.Debugf("%v connection established.", u.Scheme)

	// Disable Nagle so handshake/finalisation messages do not wait on
	// a coalesce timer; harmless on non-TCP transports.
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	start := time.Now()

	// Handle the new connection.
	if c.onConnEstablished(conn, dialCtx.Done()) {
		// Canceled with a connection established.
		c.log.Debugf("Existing connection canceled.")
		return true
	}

	// Connection died. Sessions that die young escalate the backoff
	// even though the handshake succeeded, so a peer that accepts and
	// immediately kills sessions cannot hold us in a synchronized
	// reconnect storm; long-lived sessions earn a fresh start.
	c.log.Debugf("Connection terminated, will reconnect.")
	if time.Since(start) < retryIncrement {
		c.retryDelay += retryIncrement
		if c.retryDelay > maxRetryDelay {
			c.retryDelay = maxRetryDelay
		}
	} else {
		c.retryDelay = 0
	}
	return false // Continue to next address
}

// initializeConnection sets up the dial context, dialer, and credentials
func (c *outgoingConn) initializeConnection() (context.Context, context.CancelFunc, net.Dialer, wire.PeerCredentials) {
	// Sigh, I assume the correct thing to do is to use context for everything,
	// but the whole package feels like a shitty hack to make up for the fact
	// that Go lacks a real object model.
	//
	// So, use the context stuff via a bunch of shitty hacks to make up for the
	// fact that the server doesn't use context everywhere instead.
	dialCtx, cancelFn := context.WithCancel(context.Background())

	dialer := net.Dialer{
		KeepAlive: time.Duration(c.co.Server().cfg.KeepAliveInterval) * time.Millisecond,
		Timeout:   time.Duration(c.co.Server().cfg.ConnectTimeout) * time.Millisecond,
	}

	go func() {
		// Bolt a bunch of channels to the dial canceler, such that closing
		// either channel results in the dial context being canceled.
		select {
		case <-c.co.CloseAllCh():
			cancelFn()
		case <-dialCtx.Done():
		}
	}()

	identityHash := hash.Sum256(c.dst.IdentityKey)
	linkPubKey, err := c.scheme.UnmarshalBinaryPublicKey(c.dst.LinkKey)
	if err != nil {
		panic(err)
	}
	dialCheckCreds := wire.PeerCredentials{
		AdditionalData: identityHash[:],
		PublicKey:      linkPubKey,
	}

	return dialCtx, cancelFn, dialer, dialCheckCreds
}

// validatePKIAndUpdateCredentials checks PKI validity and updates credentials if needed
func (c *outgoingConn) validatePKIAndUpdateCredentials(dialCheckCreds *wire.PeerCredentials) bool {
	// Check to see if the connection should be made in the first
	// place by seeing if the connection is in the PKI. Without
	// something like this, stale connections can get stuck in the
	// dialing state since the Connector relies on outgoingConnection
	// objects to remove themselves from the connection table.

	// Extract node ID from credentials
	var nodeID [sConstants.NodeIDLength]byte
	copy(nodeID[:], dialCheckCreds.AdditionalData)

	// Check if the replica is in the current PKI document
	replicaDesc, isReplica := c.co.Server().PKIWorker.replicas.GetReplicaDescriptor(&nodeID)
	if isReplica {
		// Verify link key matches
		keyblob, err := dialCheckCreds.PublicKey.MarshalBinary()
		if err != nil {
			panic(err)
		}
		isValid := hmac.Equal(replicaDesc.LinkKey, keyblob)
		if isValid {
			linkPubKey, err := c.scheme.UnmarshalBinaryPublicKey(replicaDesc.LinkKey)
			if err != nil {
				panic(err)
			}
			dialCheckCreds.PublicKey = linkPubKey
			return true
		} else {
			c.log.Debugf("Bailing out of Dial loop, link key mismatch.")
			return false
		}
	} else {
		c.log.Debugf("Bailing out of Dial loop, no longer in PKI.")
		return false
	}
}

func (c *outgoingConn) onConnEstablished(conn net.Conn, closeCh <-chan struct{}) (wasHalted bool) {
	defer func() {
		c.log.Debugf("TCP connection closed. (wasHalted: %v)", wasHalted)
		conn.Close()
	}()

	// Allocate the session struct.
	// For replica-to-replica connections, we send our own identity hash
	// as AdditionalData so the receiving replica can authenticate us
	identityHash := hash.Sum256From(c.co.Server().identityPublicKey)
	cfg := &wire.SessionConfig{
		KEMScheme:         c.scheme,
		Geometry:          c.geo,
		Authenticator:     c,
		AdditionalData:    identityHash[:],
		AuthenticationKey: c.co.Server().linkKey,
		RandomReader:      rand.Reader,
		HandshakeTimeout:  time.Duration(c.co.Server().cfg.HandshakeTimeout) * time.Millisecond,
		// No idle read deadline. The earlier 2*ProxyRequestTimeout bound
		// existed because a peer that never replied parked the egress
		// goroutine on RecvCommand, stalling everything queued for that
		// peer. Sends are no longer gated on replies, so a silent peer
		// stalls nothing: reading happens on its own goroutine and each
		// proxy waiter fails over on its own budget. Dead peers are
		// detected by TCP keepalive, matching this replica's incoming
		// side and the courier.
		//
		// The decoy-traffic specification, section 5, refines this: with
		// decoys enabled a healthy link's inter-arrival gaps are
		// exponential at LambdaR, so the read deadline should be
		// SafetyCap(LambdaR) and silence past it is near-certain proof
		// the peer is gone. That refinement belongs to both the courier
		// and the replica at once and is left to its own change;
		// common.SafetyCap already exists for it.
		ReadTimeout: noIdleReadTimeout,
	}
	envelopeScheme := nikeschemes.ByName(c.co.(*Connector).server.cfg.ReplicaNIKEScheme)
	isInitiator := true
	w, err := wire.NewStorageReplicaSession(cfg, envelopeScheme, isInitiator)
	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		return
	}
	defer w.Close()

	// Bind the session to the conn, handshake, authenticate.
	timeoutMs := time.Duration(c.co.Server().cfg.HandshakeTimeout) * time.Millisecond
	handshakeStart := time.Now()
	if err = w.Initialize(context.Background(), conn); err != nil {
		handshakeElapsed := time.Since(handshakeStart)
		state := "other"
		if he, ok := wire.GetHandshakeError(err); ok {
			state = string(he.State)
		} else if wire.IsNoHandshakeBytesError(err) {
			state = "premature_close"
		}
		handshakeinstrument.HandshakeFailure("outgoing", state)
		handshakeinstrument.HandshakeDuration("outgoing", "failure", handshakeElapsed)

		localAddr := ""
		if conn.LocalAddr() != nil {
			localAddr = conn.LocalAddr().String()
		}

		remoteAddr := ""
		if conn.RemoteAddr() != nil {
			remoteAddr = conn.RemoteAddr().String()
		}

		peerIdentityHash := hash.Sum256(c.dst.IdentityKey)

		var descriptorAddrs []string
		for _, transport := range cpki.ClientTransports {
			descriptorAddrs = append(descriptorAddrs, c.dst.Addresses[transport]...)
		}

		if he, ok := wire.GetHandshakeError(err); ok {
			he.WithPeerName(c.dst.Name)
		}

		c.log.Errorf(
			"Handshake failed peer=%s identity_hash=%x descriptor_addrs=%s local=%s remote=%s after=%v timeout=%v: %v",
			c.dst.Name,
			peerIdentityHash[:],
			strings.Join(descriptorAddrs, ","),
			localAddr,
			remoteAddr,
			handshakeElapsed,
			timeoutMs,
			err,
		)
		c.log.Debugf("Handshake failure details:\n%s", wire.GetDebugError(err))
		return
	}
	handshakeElapsed := time.Since(handshakeStart)
	handshakeinstrument.HandshakeDuration("outgoing", "success", handshakeElapsed)
	c.log.Debugf("Handshake completed in %v", handshakeElapsed)

	c.retryDelay = 0 // Reset the retry delay on successful handshakes.

	// Any exit of this session fast-fails proxy requests waiting on
	// this peer, so their failover proceeds immediately instead of
	// burning the full ProxyRequestTimeout against a dead session.
	peerIDHash := hash.Sum256(c.dst.IdentityKey)
	defer c.co.Server().proxyManager.FailPeer(peerIDHash)

	// Ordered so that the flag falls before FailPeer runs: a request
	// dispatched in the gap sees no session and is failed by
	// dispatchCommand rather than parked on a queue nothing will drain.
	c.sessionUp.Store(true)
	defer c.sessionUp.Store(false)

	// Set up the outgoing sender for fixed-throughput traffic.
	// On each tick of the uniform random timer, send a real command
	// if the queue has one, otherwise send a decoy.
	outCh := make(chan commands.Command, c.co.Server().cfg.OutgoingQueueSize)
	nikeScheme := nikeschemes.ByName(c.co.(*Connector).server.cfg.ReplicaNIKEScheme)
	cmds := commands.NewStorageReplicaCommands(c.geo, nikeScheme)
	sender := newOutgoingSender(c.ch, outCh, c.co.Server().cfg.DisableDecoyTraffic, c.co.Server().LogBackend(), cmds, c.dst.Name)

	// We must call UpdateRate with a real LambdaR before activating the
	// sender. Skipping it (or accepting a zero LambdaR from a stale or
	// uninitialised cache) leaves ExpDist.averageRate at 0 and the
	// sender silently never ticks for the lifetime of this session.
	if !applyOutgoingLambdaR(sender, c.co.Server().PKIWorker, c.log) {
		c.log.Errorf("aborting outgoing connection: unable to obtain a non-zero LambdaR from the PKI")
		sender.Halt()
		return
	}
	sender.UpdateConnectionStatus(true)

	// Channel to signal the writer to drain and exit.
	egressDoneCh := make(chan struct{})

	// One goroutine writes to the session and one reads from it. They
	// may run concurrently: SendCommand and RecvCommand take disjoint
	// locks over disjoint Noise states and arm disjoint deadlines. Two
	// concurrent writers would not be safe, and there is exactly one.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.sendWorker(w, outCh, egressDoneCh)
	}()
	recvCh := c.startPeerReader(w, egressDoneCh)

	// Start the reauthenticate ticker.
	reauthMs := time.Duration(c.co.Server().cfg.ReauthInterval) * time.Millisecond
	reauth := time.NewTicker(reauthMs)
	defer reauth.Stop()

	// The reader is deliberately not waited on: it may be parked in
	// RecvCommand, which only returns once the deferred conn.Close
	// runs, so waiting for it here would deadlock. It exits on its own
	// the moment the connection closes.
	shutdown := func() {
		sender.UpdateConnectionStatus(false)
		sender.Halt()
		close(egressDoneCh)
		wg.Wait()
	}

	for {
		select {
		case <-closeCh:
			wasHalted = true
			shutdown()
			return
		case <-reauth.C:
			creds, err := w.PeerCredentials()
			if err != nil {
				c.log.Debugf("replica outgoingConn: Session fail: %s", err)
				shutdown()
				return
			}
			if !c.reauthOutcome(c.IsPeerValid(creds)) {
				shutdown()
				return
			}
		case rawCmd, ok := <-recvCh:
			if !ok {
				c.log.Debugf("replica outgoingConn: peer reader exited, tearing down session.")
				shutdown()
				return
			}
			if !c.handleCommand(rawCmd) {
				shutdown()
				return
			}
		case <-c.egressErrCh:
			// The writer hit a send error.
			shutdown()
			return
		}
	}
}

// startPeerReader runs the only goroutine that reads from the session,
// handing each inbound command to the event loop. Closing the returned
// channel is how the reader reports that the session is finished.
//
// This goroutine is deliberately not waited on at shutdown. It parks in
// RecvCommand, which returns only once the connection is closed, so
// waiting for it before running onConnEstablished's deferred closes
// would deadlock. It is not leaked either: both deferred closes reach
// the same net.Conn (wire.Session.Close closes it too), and a closed
// conn fails the in-flight io.ReadFull immediately, so the reader exits
// a moment after the session does.
//
// Nothing here waits for the reply to any particular command. Replies
// are demultiplexed by envelope hash, so they may arrive in any order
// and at any time relative to the commands that provoked them.
func (c *outgoingConn) startPeerReader(w wire.SessionInterface, doneCh <-chan struct{}) chan commands.Command {
	recvCh := make(chan commands.Command, 1)
	go func() {
		defer close(recvCh)
		for {
			rawCmd, err := w.RecvCommand(context.Background())
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				return
			}
			select {
			case recvCh <- rawCmd:
			case <-doneCh:
				return
			case <-c.co.CloseAllCh():
				return
			}
		}
	}()
	return recvCh
}

// sendWorker runs the only goroutine that writes to the session. It
// takes whatever the LambdaR-paced sender hands it and puts it on the
// wire, and never waits for a reply.
//
// That is the whole point. The decoy-traffic specification, section 3,
// requires that sends are never gated on replies: the Poisson clock is
// the sole pacing authority. Gating them, as this connection used to,
// meant a slow peer backed up the outgoing queue until the ExpDist
// ticks themselves stalled, so the decoy stream fell silent exactly
// when a peer was slow. That couples observable link timing to replica
// processing latency, which is the correlation the fixed-throughput
// design exists to deny an observer.
func (c *outgoingConn) sendWorker(w wire.SessionInterface, outCh chan commands.Command, doneCh <-chan struct{}) {
	for {
		select {
		case <-doneCh:
			// Drain whatever the sender already handed us.
			for {
				select {
				case cmd := <-outCh:
					c.sendCommand(w, cmd) // return intentionally discarded: shutdown is already underway
				default:
					return
				}
			}
		case cmd := <-outCh:
			if !c.sendCommand(w, cmd) {
				return
			}
		}
	}
}

// sendCommand puts one command on the wire. Returns false if the
// connection should be closed, which any send error requires.
//
// There is no softer option. wire.Session.SendCommand rekeys the
// transport state before it writes and marks the session invalid on any
// write error, both by design ("All write errors are fatal"). So by the
// time we see the error the Noise keystream has already advanced past
// this command and the session refuses further sends, which makes a
// local retry not merely conservative to avoid but impossible: it would
// encrypt under a key the peer will never use. Tearing the session down
// and letting the reconnect loop redial with backoff is the only way
// back.
func (c *outgoingConn) sendCommand(w wire.SessionInterface, cmd commands.Command) bool {
	_, isDecoy := cmd.(*commands.ReplicaDecoy)
	if err := w.SendCommand(context.Background(), cmd); err != nil {
		if !isDecoy && !failUndeliverableProxyRequest(c.co, c.log, cmd) {
			c.log.Debugf("SendCommand failed: %v, queuing for retry", err)
			idHash := hash.Sum256(c.dst.IdentityKey)
			c.co.QueueForRetry(cmd, idHash)
		}
		select {
		case c.egressErrCh <- struct{}{}:
		default:
		}
		return false
	}
	return true
}

// handleCommand processes one command read from the peer. Returns false
// if the connection should be closed.
//
// Nothing here is matched to "the command we just sent", because there
// is no such thing once sends stop waiting for replies. Every reply
// that needs attribution carries its own: a ReplicaMessageReply is
// routed by envelope hash.
func (c *outgoingConn) handleCommand(response commands.Command) bool {
	switch responseCmd := response.(type) {
	case *commands.NoOp:
		c.log.Debugf("replica outgoingConn: Received NoOp.")
	case *commands.Disconnect:
		c.log.Debugf("replica outgoingConn: Received Disconnect from peer.")
		return false
	case *commands.ReplicaDecoy:
		// Expected response to our decoy
	case *commands.ReplicaWriteReply:
		c.handleReplicaWriteReply(responseCmd)
	case *commands.ReplicaMessageReply:
		c.log.Debugf("replica outgoingConn: Received ReplicaMessageReply error code: %d", responseCmd.ErrorCode)
		if c.co.Server().ProxyManager() == nil {
			c.log.Debugf("replica outgoingConn: ReplicaMessageReply received but proxy manager is nil")
			return true
		}
		if c.co.Server().ProxyManager().HandleReply(responseCmd) {
			c.log.Debugf("replica outgoingConn: ReplicaMessageReply routed to proxy manager")
		} else {
			c.log.Debugf("replica outgoingConn: ReplicaMessageReply not handled by proxy manager")
		}
	default:
		// A staggered fleet means a newer peer may legitimately send
		// command types this build does not handle yet. Tolerate them:
		// tearing the session down would orphan every in-flight reply.
		c.warnUnknownCommandOnce(responseCmd)
	}
	return true
}

// handleReplicaWriteReply records the outcome a peer reported for a
// replication write.
//
// A transient error is no longer retried, because ReplicaWriteReply
// carries an error code and nothing else: it names no BoxID, so on a
// link where replies arrive out of order it cannot be attributed to the
// write that produced it. The previous code retried whichever command
// happened to have been sent last, which re-sent an unrelated write and,
// when that command was a decoy, silently dropped the failed one. A
// counted drop is the honest version of what was already happening.
//
// The box is not abandoned: an under-replicated box is healed by
// read-repair when it is next read, and by Rebalance over longer
// outages.
func (c *outgoingConn) handleReplicaWriteReply(reply *commands.ReplicaWriteReply) {
	switch classifyReplicationReply(reply.ErrorCode) {
	case replicationReplyOK:
		c.log.Debugf("replica outgoingConn: Received ReplicaWriteReply error code: %d", reply.ErrorCode)
	case replicationReplyRetry:
		c.log.Warningf("replica outgoingConn: peer %s replied with transient error %d; the reply names no BoxID so it cannot be retried",
			c.dst.Name, reply.ErrorCode)
		instrument.DroppedByReason("peer_transient_error_unattributable")
	case replicationReplyDrop:
		c.log.Warningf("replica outgoingConn: peer replied with permanent error %d, dropping ReplicaWrite (retry would not help)",
			reply.ErrorCode)
		instrument.DroppedByReason("peer_permanent_error")
	}
}

// warnUnknownCommandOnce logs an unhandled-but-decodable command type once
// per type for this connection. Only called from the connection-event-loop goroutine.
func (c *outgoingConn) warnUnknownCommandOnce(cmd commands.Command) {
	name := fmt.Sprintf("%T", cmd)
	if c.unknownCmdSeen == nil {
		c.unknownCmdSeen = make(map[string]bool)
	}
	if !c.unknownCmdSeen[name] {
		c.unknownCmdSeen[name] = true
		c.log.Warningf("Ignoring unhandled command type %s from peer %s (newer peer?)", name, c.dst.Name)
	}
}

func newOutgoingConn(co GenericConnector, dst *cpki.ReplicaDescriptor, geo *geo.Geometry, scheme kem.Scheme) *outgoingConn {
	c := &outgoingConn{
		scheme:      scheme,
		geo:         geo,
		co:          co,
		dst:         dst,
		ch:          make(chan commands.Command, co.Server().cfg.OutgoingQueueSize),
		id:          atomic.AddUint64(&outgoingConnID, 1), // Diagnostic only, wrapping is fine.
		egressErrCh: make(chan struct{}, 1),
	}
	c.log = co.Server().LogBackend().GetLogger(fmt.Sprintf("replica outgoing:%d", c.id))

	c.log.Debugf("New outgoing connection: %+v", dst)

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection map.

	return c
}

// applyOutgoingLambdaR pushes a non-zero LambdaR into the sender's
// ExpDist before the sender is activated. It tries the PKI cache
// first; if that yields no usable rate, it forces a fresh PKI fetch
// and tries once more. Returns true iff UpdateRate was successfully
// called with a real rate.
func applyOutgoingLambdaR(sender *outgoingSender, pkiWorker *PKIWorker, log *logging.Logger) bool {
	if tryUpdateOutgoingRateFromCache(sender, pkiWorker, log) {
		return true
	}
	log.Warningf("PKI cache lacks a usable LambdaR; force-fetching")
	if err := pkiWorker.ForceFetchPKI(); err != nil {
		log.Errorf("force-fetch PKI failed: %v", err)
		return false
	}
	return tryUpdateOutgoingRateFromCache(sender, pkiWorker, log)
}

func tryUpdateOutgoingRateFromCache(sender *outgoingSender, pkiWorker *PKIWorker, log *logging.Logger) bool {
	doc := pkiWorker.LastCachedPKIDocument()
	if doc == nil {
		return false
	}
	rate, err := common.LambdaRateToMs(doc.LambdaR)
	if err != nil {
		log.Errorf("Invalid LambdaR %v in PKI document: %v", doc.LambdaR, err)
		return false
	}
	sender.UpdateRate(rate)
	return true
}
