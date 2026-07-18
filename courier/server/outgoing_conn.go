// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	kpcommon "github.com/katzenpost/katzenpost/common"

	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/wire/handshakeinstrument"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/courier/server/instrument"
	"github.com/katzenpost/katzenpost/quic/common"
)

var outgoingConnID uint64

const KeepAliveInterval = 3 * time.Minute

// noIdleReadTimeout effectively disables the wire session's idle read
// deadline; dead peers are detected by TCP keepalive.
const noIdleReadTimeout = 24 * 365 * time.Hour

type outgoingConn struct {
	worker.Worker

	courier    *Courier
	linkScheme kem.Scheme
	cfg        *config.Config
	co         GenericConnector
	log        *logging.Logger

	dst    *cpki.ReplicaDescriptor
	sender *sender

	id         uint64
	retryDelay time.Duration

	// unknownCmdSeen dedups unhandled-command warnings per type.
	// Touched only by the event loop goroutine.
	unknownCmdSeen map[string]bool

	// reauthFailures counts consecutive reauthentication failures.
	// Touched only by the event loop goroutine.
	reauthFailures int
}

func (c *outgoingConn) IsPeerValid(creds *wire.PeerCredentials) bool {
	// At a minimum, the peer's credentials should match what we started out
	// with. This is enforced even if mix authentication is disabled.

	// Helper function to get peer name
	getPeerName := func() string {
		if doc := c.co.Server().PKI.PKIDocument(); doc != nil {
			var adHash [32]byte
			copy(adHash[:], creds.AdditionalData)
			if node, err := doc.GetNodeByKeyHash(&adHash); err == nil {
				return node.Name
			}
		}
		return "unknown"
	}

	idHash := hash.Sum256(c.dst.IdentityKey)
	if !hmac.Equal(idHash[:], creds.AdditionalData) {
		peerName := getPeerName()
		c.log.Warningf("courier/outgoing: IsPeerValid(): Identity hash mismatch for peer '%s'", peerName)
		c.log.Warningf("courier/outgoing: IsPeerValid(): Expected identity hash: %x", idHash[:])
		c.log.Warningf("courier/outgoing: IsPeerValid(): Received identity hash: %x", creds.AdditionalData)
		c.log.Warningf("courier/outgoing: IsPeerValid(): Expected identity key (raw): %x", c.dst.IdentityKey)
		c.log.Warningf("courier/outgoing: IsPeerValid(): Received link key: %s", strings.TrimSpace(kempem.ToPublicPEMString(creds.PublicKey)))
		return false
	}
	keyblob, err := creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if !hmac.Equal(c.dst.LinkKey, keyblob) {
		peerName := getPeerName()
		c.log.Warningf("courier/outgoing: IsPeerValid(): Link key mismatch for peer '%s'", peerName)
		c.log.Warningf("courier/outgoing: IsPeerValid(): Expected link key (raw): %x", c.dst.LinkKey)
		c.log.Warningf("courier/outgoing: IsPeerValid(): Received link key: %s", strings.TrimSpace(kempem.ToPublicPEMString(creds.PublicKey)))
		c.log.Warningf("courier/outgoing: IsPeerValid(): Identity hash: %x", creds.AdditionalData)
		return false
	}

	// Query the PKI to figure out if we can send or not, and to ensure that
	// the peer is listed in a PKI document that's valid.
	var isValid bool
	_, isValid = c.co.Server().PKI.AuthenticateReplicaConnection(creds)

	if !isValid {
		peerName := getPeerName()
		c.log.Warningf("courier/outgoing: IsPeerValid(): Failed to authenticate peer '%s' via latest PKI doc", peerName)
		c.log.Warningf("courier/outgoing: IsPeerValid(): Remote Peer Credentials: name=%s, identity_hash=%x, link_key=%s", peerName, creds.AdditionalData, strings.TrimSpace(kempem.ToPublicPEMString(creds.PublicKey)))
	}
	return isValid
}

func (c *outgoingConn) dispatchMessage(mesg *commands.ReplicaMessage) error {
	req := &courierSenderRequest{
		ReplicaMessage: mesg,
		EnqueuedAt:     time.Now(),
	}
	select {
	case c.sender.in <- req:
		instrument.EnqueueTotal(c.dst.Name)
		instrument.QueueLength(c.dst.Name, len(c.sender.in))
		return nil
	case <-c.HaltCh():
		return fmt.Errorf("dispatch to %s: halted", c.dst.Name)
	default:
		// A full queue to a disconnected peer must never block the
		// caller: the synchronous copy path dispatches before it
		// arms its own reply timeout.
		instrument.DroppedByReason("dispatch_queue_full")
		return fmt.Errorf("dispatch to %s: queue full", c.dst.Name)
	}
}

func (c *outgoingConn) updateDecoyRate(rate uint64) {
	c.sender.UpdateRate(rate)
}

func (c *outgoingConn) worker() {
	var (
		// XXX NOTE(david): we might need to adjust these to be aligned with our pki worker thread
		retryIncrement = epochtime.Period / 64
		maxRetryDelay  = epochtime.Period / 8
	)

	defer func() {
		c.log.Debugf("Halting connect worker.")
		c.co.OnClosedConn(c)
		c.sender.Halt()
	}()

	dialCtx, dialer, dialCheckCreds := c.initializeWorker()
	defer dialCtx.cancelFn()

	c.runConnectionLoop(dialCtx, dialer, dialCheckCreds, retryIncrement, maxRetryDelay)
}

// workerContext holds the context and cancellation function for the worker
type workerContext struct {
	context.Context
	cancelFn context.CancelFunc
}

// initializeWorker sets up the dial context, dialer, and credentials for the worker
func (c *outgoingConn) initializeWorker() (*workerContext, *net.Dialer, *wire.PeerCredentials) {
	dialCtx, cancelFn := context.WithCancel(context.Background())

	dialer := &net.Dialer{
		KeepAlive: KeepAliveInterval,
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
	linkPubKey, err := c.linkScheme.UnmarshalBinaryPublicKey(c.dst.LinkKey)
	if err != nil {
		panic(err)
	}

	dialCheckCreds := &wire.PeerCredentials{
		AdditionalData: identityHash[:],
		PublicKey:      linkPubKey,
	}

	return &workerContext{dialCtx, cancelFn}, dialer, dialCheckCreds
}

// runConnectionLoop handles the main connection establishment loop
func (c *outgoingConn) runConnectionLoop(dialCtx *workerContext, dialer *net.Dialer, dialCheckCreds *wire.PeerCredentials, retryIncrement, maxRetryDelay time.Duration) {
	for {
		if !c.validateAndUpdateDescriptor(dialCheckCreds) {
			return
		}

		dstAddrs := c.collectDestinationAddresses()
		if len(dstAddrs) == 0 {
			c.log.Warningf("Bailing out of Dial loop, no suitable addresses found.")
			return
		}

		if c.attemptConnections(dialCtx, dialer, dstAddrs, retryIncrement, maxRetryDelay) {
			return
		}
	}
}

// validateAndUpdateDescriptor checks PKI validity and updates the descriptor if needed
func (c *outgoingConn) validateAndUpdateDescriptor(dialCheckCreds *wire.PeerCredentials) bool {
	if desc, isValid := c.co.Server().PKI.AuthenticateReplicaConnection(dialCheckCreds); isValid {
		// The list of addresses could have changed, authenticateConnection
		// will return the most "current" descriptor on success, so update
		// the cached pointer.
		if desc != nil {
			c.dst = desc
			linkPubKey, err := c.linkScheme.UnmarshalBinaryPublicKey(c.dst.LinkKey)
			if err != nil {
				panic(err)
			}
			dialCheckCreds.PublicKey = linkPubKey
		}
		return true
	}

	c.log.Debugf("Bailing out of Dial loop, no longer in PKI.")
	return false
}

// collectDestinationAddresses flattens the lists of addresses to dial to
func (c *outgoingConn) collectDestinationAddresses() []string {
	var dstAddrs []string
	for _, t := range cpki.ClientTransports {
		if v, ok := c.dst.Addresses[t]; ok {
			dstAddrs = append(dstAddrs, v...)
		}
	}
	return dstAddrs
}

// attemptConnections tries to connect to each address and returns true if worker should exit
func (c *outgoingConn) attemptConnections(dialCtx *workerContext, dialer *net.Dialer, dstAddrs []string, retryIncrement, maxRetryDelay time.Duration) bool {
	for _, addr := range dstAddrs {
		if c.handleRetryDelay(dialCtx, retryIncrement, maxRetryDelay) {
			return true // Canceled during retry delay
		}

		conn, shouldReturn := c.dialAddress(dialCtx, dialer, addr)
		if shouldReturn {
			return true
		}
		if conn == nil {
			continue // Failed to connect, try next address
		}

		start := time.Now()
		if c.onConnEstablished(conn, dialCtx.Done()) {
			// Canceled with a connection established.
			c.log.Debugf("Existing connection canceled.")
			return true
		}

		// Connection died. Sessions that die young escalate the
		// backoff even though the handshake succeeded, so a peer
		// that accepts and immediately kills sessions cannot hold
		// us in a synchronized reconnect storm; long-lived sessions
		// earn a fresh start.
		c.log.Debugf("Connection terminated, will reconnect.")
		if time.Since(start) < retryIncrement {
			c.retryDelay += retryIncrement
			if c.retryDelay > maxRetryDelay {
				c.retryDelay = maxRetryDelay
			}
		} else {
			c.retryDelay = 0
		}
		break
	}
	return false
}

// handleRetryDelay manages the retry delay logic and returns true if canceled
func (c *outgoingConn) handleRetryDelay(dialCtx *workerContext, retryIncrement, maxRetryDelay time.Duration) bool {
	select {
	case <-time.After(kpcommon.JitterDelay(c.retryDelay)):
		// Back off incrementally on reconnects.
		c.retryDelay += retryIncrement
		if c.retryDelay > maxRetryDelay {
			c.retryDelay = maxRetryDelay
		}
		return false
	case <-dialCtx.Done():
		// Canceled mid-retry delay.
		c.log.Debugf("(Re)connection attempts canceled.")
		return true
	}
}

// dialAddress attempts to dial a single address and returns the connection and whether worker should return
func (c *outgoingConn) dialAddress(dialCtx *workerContext, dialer *net.Dialer, addr string) (net.Conn, bool) {
	u, err := url.Parse(addr)
	if err != nil {
		c.log.Warningf("Failed to parse addr: %v", err)
		return nil, false
	}
	c.log.Debugf("Dialing: %v", u.Host)

	conn, err := common.DialURL(u, dialCtx.Context, dialer.DialContext)
	select {
	case <-dialCtx.Done():
		// Canceled.
		if conn != nil {
			conn.Close()
		}
		return nil, true
	default:
		if err != nil {
			c.log.Warningf("Failed to connect to '%v': %v", u.Host, err)
			return nil, false
		}
	}

	c.log.Debugf("%v connection established.", u.Scheme)
	// Disable Nagle so handshake/finalisation messages do not wait on
	// a coalesce timer; harmless on non-TCP transports.
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}
	return conn, false
}

// applyPKILambdaR tries to push a non-zero LambdaR (and its max delay)
// into the sender's ExpDist. The cached PKI document is consulted
// first; if it is missing or carries an unusable LambdaR, we force a
// fresh fetch from the directory authorities and try once more.
// Returns true if and only if UpdateRate was called with a usable
// rate. The caller must not activate the sender on a false return,
// because ExpDist with averageRate == 0 silently never ticks.
func (c *outgoingConn) applyPKILambdaR() bool {
	if c.tryUpdateRateFromCache() {
		return true
	}
	c.log.Warningf("PKI cache lacks a usable LambdaR; force-fetching")
	if err := c.co.Server().PKI.ForceFetchPKI(); err != nil {
		c.log.Errorf("force-fetch PKI failed: %v", err)
		return false
	}
	return c.tryUpdateRateFromCache()
}

func (c *outgoingConn) tryUpdateRateFromCache() bool {
	doc := c.co.Server().PKI.LastCachedPKIDocument()
	if doc == nil {
		return false
	}
	rate, err := kpcommon.LambdaRateToMs(doc.LambdaR)
	if err != nil {
		c.log.Errorf("Invalid LambdaR %v in PKI document: %v", doc.LambdaR, err)
		return false
	}
	c.sender.UpdateRate(rate)
	return true
}

func (c *outgoingConn) onConnEstablished(conn net.Conn, closeCh <-chan struct{}) (wasHalted bool) {
	defer func() {
		c.log.Debugf("TCP connection closed. (wasHalted: %v)", wasHalted)
		conn.Close()
	}()

	w, err := c.setupSession(conn)
	if err != nil {
		return
	}
	defer w.Close()

	// We must call UpdateRate with a real LambdaR before activating the
	// sender. Skipping it (or accepting a zero LambdaR from a stale or
	// uninitialised cache) leaves ExpDist.averageRate at 0, in which
	// case the sender's worker schedules its next tick at MaxInt64 and
	// never fires for the lifetime of this session. That manifests as
	// a courier whose outbound stream silently dries up.
	if !c.applyPKILambdaR() {
		c.log.Errorf("aborting connection: unable to obtain a non-zero LambdaR from the PKI")
		return
	}
	c.sender.UpdateConnectionStatus(true)
	instrument.PeerConnected(c.dst.Name, true)
	defer func() {
		c.sender.UpdateConnectionStatus(false)
		instrument.PeerConnected(c.dst.Name, false)
	}()

	sessionDoneCh := make(chan struct{})
	defer close(sessionDoneCh)
	receiveCmdCh := c.startPeerReader(w, sessionDoneCh)
	cmdCh, cmdCloseCh := c.startCommandSender(w)
	defer close(cmdCh)

	reauth := c.startReauthTicker()
	defer reauth.Stop()

	return c.runEventLoop(w, closeCh, reauth, cmdCh, cmdCloseCh, receiveCmdCh)
}

// setupSession creates and initializes a wire session for the connection
func (c *outgoingConn) setupSession(conn net.Conn) (*wire.Session, error) {
	cfg := &wire.SessionConfig{
		KEMScheme:         c.linkScheme,
		Geometry:          c.cfg.SphinxGeometry,
		Authenticator:     c,
		AdditionalData:    []byte{},
		AuthenticationKey: c.co.Server().linkPrivKey,
		RandomReader:      rand.Reader,
		HandshakeTimeout:  time.Duration(c.co.Server().cfg.HandshakeTimeout) * time.Millisecond,
		ReadTimeout:       noIdleReadTimeout,
		WriteTimeout:      time.Duration(c.co.Server().cfg.WriteTimeout) * time.Millisecond,
	}

	envelopeScheme := nikeSchemes.ByName(c.cfg.EnvelopeScheme)
	isInitiator := true
	w, err := wire.NewStorageReplicaSession(cfg, envelopeScheme, isInitiator)
	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		return nil, err
	}

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
		return nil, err
	}
	handshakeinstrument.HandshakeDuration("outgoing", "success", time.Since(handshakeStart))
	c.log.Debugf("Handshake completed in %v", time.Since(handshakeStart))
	c.retryDelay = 0 // Reset the retry delay on successful handshakes.
	return w, nil
}

// startPeerReader starts a goroutine to read commands from the peer.
// Every send also selects on sessionDoneCh: when the event loop has
// already returned for another reason (reauth failure, sender death,
// Disconnect), nobody consumes this channel and outgoingConn.Halt is
// never called on per-session teardown, so a bare send here leaked one
// goroutine per reconnect.
func (c *outgoingConn) startPeerReader(w *wire.Session, sessionDoneCh <-chan struct{}) chan interface{} {
	receiveCmdCh := make(chan interface{}, 1)
	c.Go(func() {
		defer close(receiveCmdCh)
		for {
			rawCmd, err := w.RecvCommand(context.Background())
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				select {
				case <-c.HaltCh():
				case <-sessionDoneCh:
				case receiveCmdCh <- err:
				}
				return
			}
			if !isReplicaDecoy(rawCmd) {
				c.log.Debugf("Received command from replica: %T", rawCmd)
			}
			select {
			case <-c.HaltCh():
				return
			case <-sessionDoneCh:
				return
			case receiveCmdCh <- rawCmd:
			}
		}
	})
	return receiveCmdCh
}

// startCommandSender starts a goroutine to send commands to the peer
func (c *outgoingConn) startCommandSender(w *wire.Session) (chan commands.Command, chan error) {
	cmdCh := make(chan commands.Command)
	cmdCloseCh := make(chan error)

	go func() {
		defer close(cmdCloseCh)
		for {
			cmd, ok := <-cmdCh
			if !ok {
				return
			}

			if err := w.SendCommand(context.Background(), cmd); err != nil {
				c.log.Debugf("SendCommand failed: %v", err)
				c.requeueUnsent(cmd)
				return
			}
		}
	}()

	return cmdCh, cmdCloseCh
}

// requeueUnsent returns a real command whose wire send failed to the
// sender FIFO so the next session delivers it; decoys are pacing, not
// payload, and are simply dropped.
func (c *outgoingConn) requeueUnsent(cmd commands.Command) {
	mesg, ok := cmd.(*commands.ReplicaMessage)
	if !ok {
		return
	}
	req := &courierSenderRequest{ReplicaMessage: mesg, EnqueuedAt: time.Now()}
	select {
	case c.sender.in <- req:
		c.log.Debugf("Re-queued unsent ReplicaMessage for next session")
	default:
		instrument.DroppedByReason("send_command_failed")
	}
}

// startReauthTicker starts the reauthentication ticker
func (c *outgoingConn) startReauthTicker() *time.Ticker {
	reauthMs := time.Duration(c.co.Server().cfg.ReauthInterval) * time.Millisecond
	return time.NewTicker(reauthMs)
}

// runEventLoop handles the main event processing loop.
//
// Sends are never gated on replies: the sender's LambdaR-paced ExpDist
// is the sole pacing authority, keeping the link fixed-throughput and
// independent of replica processing latency. Replies are demultiplexed
// by EnvelopeHash (HandleReply), so no ordering between commands and
// replies is required.
func (c *outgoingConn) runEventLoop(w *wire.Session, closeCh <-chan struct{}, reauth *time.Ticker, cmdCh chan commands.Command, cmdCloseCh chan error, receiveCmdCh chan interface{}) bool {
	for {
		select {
		case <-c.HaltCh():
			return false
		case <-closeCh:
			return true
		case <-reauth.C:
			if !c.handleReauth(w) {
				return false
			}
		case req := <-c.sender.out:
			done, halted := c.handleOutgoingCommand(req.command(), cmdCh, closeCh, cmdCloseCh)
			if done {
				return halted
			}
		case <-cmdCloseCh:
			return false
		case replyCmd := <-receiveCmdCh:
			rawCmd := c.processIncomingReply(replyCmd)
			if rawCmd == nil {
				// Wire error (already logged); tear the session down.
				return false
			}
			if !c.handleCommand(rawCmd) {
				return false
			}
		}
	}
}

// reauthGraceLimit is how many consecutive reauthentication failures a
// live session survives before being torn down. Descriptor churn during
// staggered upgrades and dirauth wobble transiently drops a healthy peer
// from the newest document; severing the link on the first miss orphans
// in-flight replies for no security gain, since the peer was
// authenticated at handshake and the key material has not changed.
const reauthGraceLimit = 3

// handleReauth processes reauthentication events
func (c *outgoingConn) handleReauth(w *wire.Session) bool {
	creds, err := w.PeerCredentials()
	if err != nil {
		c.log.Debugf("Session fail: %s", err)
		return false
	}
	return c.reauthOutcome(c.IsPeerValid(creds))
}

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

// handleOutgoingCommand hands one paced command to the command-sender
// goroutine. It must also watch cmdCloseCh: the sender goroutine exits
// (closing cmdCloseCh) when a wire write fails, and with an unbuffered
// cmdCh the send would otherwise block forever, since closeCh only
// fires on connector-wide shutdown, never on per-session death. That
// wedged the event loop and permanently orphaned the replica: the
// connector resweep skips peers already present in its conn table.
//
// done reports that the event loop must return; halted is the value it
// must return (true means the worker exits, false means redial).
func (c *outgoingConn) handleOutgoingCommand(cmd commands.Command, cmdCh chan commands.Command, closeCh <-chan struct{}, cmdCloseCh <-chan error) (done, halted bool) {
	select {
	case <-c.HaltCh():
		return true, true
	case <-closeCh:
		return true, true
	case cmdCh <- cmd:
		return false, false
	case <-cmdCloseCh:
		// The sender died with this command still in hand; requeue it
		// for the next session (requeueUnsent drops decoys) and tear
		// the session down so the dial loop reconnects.
		c.log.Debugf("Command sender died with a command in hand; tearing down session")
		c.requeueUnsent(cmd)
		return true, false
	}
}

// isReplicaDecoy reports whether cmd is fixed-throughput decoy padding. The
// courier-replica link is kept at a constant rate with ReplicaDecoy commands,
// so at DEBUG they drown out the real replies; the per-command traces skip them.
func isReplicaDecoy(cmd interface{}) bool {
	_, ok := cmd.(*commands.ReplicaDecoy)
	return ok
}

// processIncomingReply processes replies from the peer
func (c *outgoingConn) processIncomingReply(replyCmd interface{}) commands.Command {
	if !isReplicaDecoy(replyCmd) {
		c.log.Debugf("Processing reply from receiveCmdCh: %T", replyCmd)
	}
	switch cmdOrErr := replyCmd.(type) {
	case commands.Command:
		return cmdOrErr
	case error:
		c.log.Errorf("Received wire protocol RecvCommand error: %s", cmdOrErr)
		return nil
	}

	return nil
}

// handleCommand processes received commands from the storage replicas
func (c *outgoingConn) handleCommand(rawCmd commands.Command) bool {
	if !isReplicaDecoy(rawCmd) {
		c.log.Debugf("Handling response command: %T", rawCmd)
	}
	switch replycmd := rawCmd.(type) {
	case *commands.NoOp:
	case *commands.Disconnect:
		c.log.Debugf("Received Disconnect from peer.")
		return false
	case *commands.ReplicaMessageReply:
		c.courier.HandleReply(replycmd)
	case *commands.ReplicaDecoy:
	default:
		// A staggered fleet means a newer replica may legitimately send
		// command types this build does not handle yet. Tolerate them:
		// tearing the session down would orphan every in-flight reply.
		c.warnUnknownCommandOnce(rawCmd)
	}

	return true
}

// warnUnknownCommandOnce logs an unhandled-but-decodable command type once
// per type for this connection. Only called from the event loop goroutine.
func (c *outgoingConn) warnUnknownCommandOnce(cmd commands.Command) {
	name := fmt.Sprintf("%T", cmd)
	if c.unknownCmdSeen == nil {
		c.unknownCmdSeen = make(map[string]bool)
	}
	if !c.unknownCmdSeen[name] {
		c.unknownCmdSeen[name] = true
		c.log.Warningf("Ignoring unhandled command type %s from replica peer %s (newer peer?)", name, c.dst.Name)
	}
}

func newOutgoingConn(co GenericConnector, dst *cpki.ReplicaDescriptor, cfg *config.Config, courier *Courier) *outgoingConn {
	linkScheme := kemSchemes.ByName(cfg.WireKEMScheme)
	idScheme := signSchemes.ByName(cfg.PKIScheme)
	envelopeScheme := nikeSchemes.ByName(cfg.EnvelopeScheme)

	c := &outgoingConn{
		linkScheme: linkScheme,
		cfg:        cfg,
		courier:    courier,
		co:         co,
		dst:        dst,
		id:         atomic.AddUint64(&outgoingConnID, 1), // Diagnostic only, wrapping is fine.
	}
	c.log = co.Server().LogBackend().GetLogger(fmt.Sprintf("courier outgoing:%d", c.id))

	senderIn := make(chan *courierSenderRequest, cfg.MaxQueueSize)
	senderOut := make(chan *courierSenderRequest, 1)
	c.sender = newSender(senderIn, senderOut, cfg.DisableDecoyTraffic, co.Server().LogBackend(), courier.cmds, dst.Name)

	c.log.Debugf("New outgoing connection: %+v", dst.DisplayWithSchemes(linkScheme, idScheme, envelopeScheme))

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection map.

	return c
}
