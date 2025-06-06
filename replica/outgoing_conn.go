// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"crypto/hmac"
	"fmt"
	"net"
	"net/url"
	"sync/atomic"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/http/common"
)

var outgoingConnID uint64

type outgoingConn struct {
	scheme kem.Scheme
	geo    *geo.Geometry
	co     GenericConnector
	log    *logging.Logger

	dst *cpki.ReplicaDescriptor
	ch  chan commands.Command

	id         uint64
	retryDelay time.Duration
}

func (c *outgoingConn) IsPeerValid(creds *wire.PeerCredentials) bool {
	// First verify the identity hash matches what we expect
	idHash := hash.Sum256(c.dst.IdentityKey)
	if !hmac.Equal(idHash[:], creds.AdditionalData) {
		c.log.Debug("OutgoingConn: Identity hash mismatch")
		return false
	}

	// Then verify the link key matches what we expect
	keyblob, err := creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if !hmac.Equal(c.dst.LinkKey, keyblob) {
		c.log.Debug("OutgoingConn: Link key mismatch")
		return false
	}

	// Verify the replica is in the current PKI document
	var nodeID [sConstants.NodeIDLength]byte
	copy(nodeID[:], creds.AdditionalData)
	_, isReplica := c.co.Server().PKIWorker.replicas.GetReplicaDescriptor(&nodeID)
	if !isReplica {
		c.log.Debug("OutgoingConn: PKI authentication failed - replica not found")
		return false
	}

	c.log.Debug("OutgoingConn: Authentication successful")
	return true
}

func (c *outgoingConn) dispatchCommand(cmd commands.Command) {
	select {
	case c.ch <- cmd:
	default:
		// Drop-tail.  This would be better as a RingChannel from the channels
		// package (Drop-head), but it doesn't provide a way to tell if the
		// item was discared or not.
		//
		// The drops here should basically only happen if the link is down,
		// since the connection worker will handle dropping commands when the
		// link is congested.
		//
		// Note: Not logging here because this would get spammy, and we may be
		// under catastrophic load, in which case we can't afford to log.
	}
}

func (c *outgoingConn) worker() {
	retryIncrement, maxRetryDelay := epochtime.Period/64, epochtime.Period/8

	defer func() {
		c.log.Debugf("Halting connect worker.")
		c.co.OnClosedConn(c)
		close(c.ch)
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
	linkPubKey, err := c.scheme.UnmarshalBinaryPublicKey(c.dst.LinkKey)
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
		if !c.validatePKIConnection(dialCheckCreds) {
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

// validatePKIConnection checks PKI validity and updates the descriptor if needed
func (c *outgoingConn) validatePKIConnection(dialCheckCreds *wire.PeerCredentials) bool {
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

		conn, shouldReturn := c.dialConnection(dialCtx, dialer, addr)
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

		// Connection died, check if we should impose retry delay
		c.log.Debugf("Connection terminated, will reconnect.")
		if time.Since(start) < retryIncrement {
			c.retryDelay = retryIncrement
		}
		break
	}
	return false
}

// handleRetryDelay manages the retry delay logic and returns true if canceled
func (c *outgoingConn) handleRetryDelay(dialCtx *workerContext, retryIncrement, maxRetryDelay time.Duration) bool {
	select {
	case <-time.After(c.retryDelay):
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

// dialConnection attempts to dial a single address and returns the connection and whether worker should return
func (c *outgoingConn) dialConnection(dialCtx *workerContext, dialer *net.Dialer, addr string) (net.Conn, bool) {
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
	return conn, false
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
	envelopeScheme := schemes.ByName(c.co.(*Connector).server.cfg.ReplicaNIKEScheme)
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
	if err = w.Initialize(conn); err != nil {
		c.log.Errorf("Handshake failed: %v", err)
		return
	}
	c.log.Debugf("Handshake completed.")
	conn.SetDeadline(time.Time{})
	c.retryDelay = 0 // Reset the retry delay on successful handshakes.

	// Start the reauthenticate ticker.
	reauthMs := time.Duration(c.co.Server().cfg.ReauthInterval) * time.Millisecond
	reauth := time.NewTicker(reauthMs)
	defer reauth.Stop()

	for {
		select {
		case <-closeCh:
			wasHalted = true
			return
		case <-reauth.C:
			// Each outgoing connection has a periodic 1/15 Hz timer to wake up
			// and re-authenticate to handle the PKI document(s) changing.
			creds, err := w.PeerCredentials()
			if err != nil {
				c.log.Debugf("replica outgoingConn: Session fail: %s", err)
				return
			}
			if !c.IsPeerValid(creds) {
				c.log.Debugf("replica outgoingConn: Disconnecting, peer reauthenticate failed.")
				return
			}
			continue
		case cmd := <-c.ch:
			if err := w.SendCommand(cmd); err != nil {
				c.log.Debugf("SendCommand failed: %v", err)
				return
			}

			response, err := w.RecvCommand()
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				return
			}
			switch responseCmd := response.(type) {
			case *commands.NoOp:
				c.log.Debugf("replica outgoingConn: Received NoOp.")
			case *commands.Disconnect:
				c.log.Debugf("replica outgoingConn: Received Disconnect from peer.")
				return
			case *commands.ReplicaWriteReply:
				c.log.Debugf("replica outgoingConn: Received ReplicaWriteReply error code: %d", responseCmd.ErrorCode)
			case *commands.ReplicaMessageReply:
				c.log.Debugf("replica outgoingConn: Received ReplicaMessageReply error code: %d", responseCmd.ErrorCode)
			default:
				c.log.Errorf("replica outgoingConn: BUG, Received unexpected command from replica peer: %s", responseCmd)
				return
			}
		}
	}
}

func newOutgoingConn(co GenericConnector, dst *cpki.ReplicaDescriptor, geo *geo.Geometry, scheme kem.Scheme) *outgoingConn {
	const maxQueueSize = 64 // TODO/perf: Tune this.

	c := &outgoingConn{
		scheme: scheme,
		geo:    geo,
		co:     co,
		dst:    dst,
		ch:     make(chan commands.Command, maxQueueSize),
		id:     atomic.AddUint64(&outgoingConnID, 1), // Diagnostic only, wrapping is fine.
	}
	c.log = co.Server().LogBackend().GetLogger(fmt.Sprintf("replica outgoing:%d", c.id))

	c.log.Debugf("New outgoing connection: %+v", dst)

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection map.

	return c
}
