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
	httpCommon "github.com/katzenpost/katzenpost/quic/common"
	"github.com/katzenpost/katzenpost/replica/instrument"
)

var outgoingConnID uint64

type outgoingConn struct {
	scheme kem.Scheme
	geo    *geo.Geometry
	co     GenericConnector
	log    *logging.Logger

	dst *cpki.ReplicaDescriptor
	ch  chan commands.Command

	id          uint64
	retryDelay  time.Duration
	egressErrCh chan struct{}
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

// validateReplicaInPKI verifies the replica is in the current PKI document
func (c *outgoingConn) validateReplicaInPKI(creds *wire.PeerCredentials) bool {
	var nodeID [sConstants.NodeIDLength]byte
	copy(nodeID[:], creds.AdditionalData)
	_, isReplica := c.co.Server().PKIWorker.replicas.GetReplicaDescriptor(&nodeID)
	if !isReplica {
		c.log.Debug("OutgoingConn: PKI authentication failed - replica not found")
		return false
	}
	return true
}

func (c *outgoingConn) dispatchCommand(cmd commands.Command) {
	select {
	case c.ch <- cmd:
		instrument.OutgoingQueueLength(c.dst.Name, len(c.ch))
	case <-c.co.CloseAllCh():
	}
}

func (c *outgoingConn) worker() {
	retryIncrement := epochtime.Period / 64
	maxRetryDelay := epochtime.Period / 8

	defer func() {
		c.log.Debugf("Halting connect worker.")
		// Drain any pending commands from the channel and queue them for retry
		// before closing. This prevents losing commands when connections fail.
		idHash := hash.Sum256(c.dst.IdentityKey)
		pendingCount := 0
		for {
			select {
			case cmd := <-c.ch:
				c.co.QueueForRetry(cmd, idHash)
				pendingCount++
			default:
				// Channel is empty
				if pendingCount > 0 {
					c.log.Debugf("Queued %d pending commands for retry after connection closed", pendingCount)
				}
				goto done
			}
		}
	done:
		c.co.OnClosedConn(c)
		close(c.ch)
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

// attemptConnectionToAddresses tries to connect to each address with retry logic
func (c *outgoingConn) attemptConnectionToAddresses(dstAddrs []string, dialCtx context.Context, dialer net.Dialer, retryIncrement, maxRetryDelay time.Duration) bool {
	for _, addr := range dstAddrs {
		select {
		case <-time.After(c.retryDelay):
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

		if c.dialAndHandleConnection(addr, dialCtx, dialer, retryIncrement) {
			return true // Connection was canceled or we should exit
		}
	}
	return false
}

// dialAndHandleConnection handles dialing to a single address and managing the connection
func (c *outgoingConn) dialAndHandleConnection(addr string, dialCtx context.Context, dialer net.Dialer, retryIncrement time.Duration) bool {
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

	start := time.Now()

	// Handle the new connection.
	if c.onConnEstablished(conn, dialCtx.Done()) {
		// Canceled with a connection established.
		c.log.Debugf("Existing connection canceled.")
		return true
	}

	// That's odd, the connection died, reconnect.
	c.log.Debugf("Connection terminated, will reconnect.")
	if time.Since(start) < retryIncrement {
		// If the connection was not alive for a sensible amount of
		// time, re-impose a reconnect delay.
		c.retryDelay = retryIncrement
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
			// The list of addresses could have changed, so update
			// the cached pointer with the current descriptor
			c.dst = replicaDesc
			linkPubKey, err := c.scheme.UnmarshalBinaryPublicKey(c.dst.LinkKey)
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
	conn.SetDeadline(time.Now().Add(timeoutMs))
	handshakeStart := time.Now()
	if err = w.Initialize(conn); err != nil {
		handshakeElapsed := time.Since(handshakeStart)

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
	c.log.Debugf("Handshake completed in %v", time.Since(handshakeStart))
	conn.SetDeadline(time.Time{})

	c.retryDelay = 0 // Reset the retry delay on successful handshakes.

	// Set up the outgoing sender for fixed-throughput traffic.
	// On each tick of the uniform random timer, send a real command
	// if the queue has one, otherwise send a decoy.
	outCh := make(chan commands.Command, c.co.Server().cfg.OutgoingQueueSize)
	nikeScheme := nikeschemes.ByName(c.co.(*Connector).server.cfg.ReplicaNIKEScheme)
	cmds := commands.NewStorageReplicaCommands(c.geo, nikeScheme)
	sender := newOutgoingSender(c.ch, outCh, c.co.Server().cfg.DisableDecoyTraffic, c.co.Server().LogBackend(), cmds, c.dst.Name)

	// LambdaR is near-constant; tolerate a one-epoch-stale doc. Skip the
	// UpdateRate call if nothing is cached — the sender will use its prior
	// rate (or stay idle on first-ever connect) and the resweep will catch up.
	if doc := c.co.Server().PKIWorker.LastCachedPKIDocument(); doc != nil {
		rate, err := common.LambdaRateToMs(doc.LambdaR)
		if err != nil {
			c.log.Errorf("Invalid LambdaR %v in PKI document: %v", doc.LambdaR, err)
		} else {
			sender.UpdateRate(rate, doc.LambdaRMaxDelay)
		}
	}
	sender.UpdateConnectionStatus(true)

	// Channel to signal egress goroutine to drain and exit
	egressDoneCh := make(chan struct{})

	// Start egress goroutine that sends commands over the wire
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.egressWorker(w, outCh, egressDoneCh)
	}()

	// Start the reauthenticate ticker.
	reauthMs := time.Duration(c.co.Server().cfg.ReauthInterval) * time.Millisecond
	reauth := time.NewTicker(reauthMs)
	defer reauth.Stop()

	// Wait for shutdown or reauth failure
	for {
		select {
		case <-closeCh:
			wasHalted = true
			sender.UpdateConnectionStatus(false)
			sender.Halt()
			close(egressDoneCh)
			wg.Wait()
			return
		case <-reauth.C:
			creds, err := w.PeerCredentials()
			if err != nil {
				c.log.Debugf("replica outgoingConn: Session fail: %s", err)
				sender.UpdateConnectionStatus(false)
				sender.Halt()
				close(egressDoneCh)
				wg.Wait()
				return
			}
			if !c.IsPeerValid(creds) {
				c.log.Debugf("replica outgoingConn: Disconnecting, peer reauthenticate failed.")
				sender.UpdateConnectionStatus(false)
				sender.Halt()
				close(egressDoneCh)
				wg.Wait()
				return
			}
		case <-c.egressErrCh:
			// Egress worker hit a send/recv error
			sender.UpdateConnectionStatus(false)
			sender.Halt()
			close(egressDoneCh)
			wg.Wait()
			return
		}
	}
}

// egressWorker reads commands from the sender output channel and sends them
// over the wire session. It handles responses and signals errors back.
func (c *outgoingConn) egressWorker(w wire.SessionInterface, outCh chan commands.Command, doneCh <-chan struct{}) {
	for {
		select {
		case <-doneCh:
			// Drain remaining commands
			for {
				select {
				case cmd := <-outCh:
					c.sendAndRecv(w, cmd)
				default:
					return
				}
			}
		case cmd := <-outCh:
			if !c.sendAndRecv(w, cmd) {
				return
			}
		}
	}
}

// sendAndRecv sends a command and processes the response.
// Returns false if the connection should be closed.
func (c *outgoingConn) sendAndRecv(w wire.SessionInterface, cmd commands.Command) bool {
	_, isDecoy := cmd.(*commands.ReplicaDecoy)
	if err := w.SendCommand(cmd); err != nil {
		if !isDecoy {
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

	response, err := w.RecvCommand()
	if err != nil {
		if !isDecoy {
			c.log.Debugf("Failed to receive command: %v, queuing for retry", err)
			idHash := hash.Sum256(c.dst.IdentityKey)
			c.co.QueueForRetry(cmd, idHash)
		}
		select {
		case c.egressErrCh <- struct{}{}:
		default:
		}
		return false
	}

	switch responseCmd := response.(type) {
	case *commands.NoOp:
		c.log.Debugf("replica outgoingConn: Received NoOp.")
	case *commands.Disconnect:
		c.log.Debugf("replica outgoingConn: Received Disconnect from peer.")
		select {
		case c.egressErrCh <- struct{}{}:
		default:
		}
		return false
	case *commands.ReplicaDecoy:
		// Expected response to our decoy
	case *commands.ReplicaWriteReply:
		switch classifyReplicationReply(responseCmd.ErrorCode) {
		case replicationReplyOK:
			c.log.Debugf("replica outgoingConn: Received ReplicaWriteReply error code: %d", responseCmd.ErrorCode)
		case replicationReplyRetry:
			c.log.Warningf("replica outgoingConn: peer replied with transient error %d, queueing ReplicaWrite for retry",
				responseCmd.ErrorCode)
			if write, ok := cmd.(*commands.ReplicaWrite); ok {
				idHash := hash.Sum256(c.dst.IdentityKey)
				c.co.QueueForRetry(write, idHash)
			}
		case replicationReplyDrop:
			c.log.Warningf("replica outgoingConn: peer replied with permanent error %d, dropping ReplicaWrite (retry would not help)",
				responseCmd.ErrorCode)
		}
	case *commands.ReplicaMessageReply:
		c.log.Debugf("replica outgoingConn: Received ReplicaMessageReply error code: %d", responseCmd.ErrorCode)
		if c.co.Server().ProxyManager() != nil {
			handled := c.co.Server().ProxyManager().HandleReply(responseCmd)
			if handled {
				c.log.Debugf("replica outgoingConn: ReplicaMessageReply routed to proxy manager")
			} else {
				c.log.Debugf("replica outgoingConn: ReplicaMessageReply not handled by proxy manager")
			}
		}
	default:
		c.log.Errorf("replica outgoingConn: BUG, Received unexpected command from replica peer: %s", responseCmd)
		select {
		case c.egressErrCh <- struct{}{}:
		default:
		}
		return false
	}
	return true
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
