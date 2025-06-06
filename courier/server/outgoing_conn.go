// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

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
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/http/common"
)

var outgoingConnID uint64

const KeepAliveInterval = 3 * time.Minute

type outgoingConn struct {
	worker.Worker

	courier    *Courier
	linkScheme kem.Scheme
	cfg        *config.Config
	co         GenericConnector
	log        *logging.Logger

	dst *cpki.ReplicaDescriptor
	ch  chan *commands.ReplicaMessage

	id         uint64
	retryDelay time.Duration
}

func (c *outgoingConn) IsPeerValid(creds *wire.PeerCredentials) bool {
	// At a minimum, the peer's credentials should match what we started out
	// with.  This is enforced even if mix authentication is disabled.

	idHash := hash.Sum256(c.dst.IdentityKey)
	if !hmac.Equal(idHash[:], creds.AdditionalData) {
		c.log.Debug("IsPeerValid false, identity hash mismatch")
		return false
	}
	keyblob, err := creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if !hmac.Equal(c.dst.LinkKey, keyblob) {
		c.log.Debug("IsPeerValid false, link key mismatch")
		return false
	}

	// Query the PKI to figure out if we can send or not, and to ensure that
	// the peer is listed in a PKI document that's valid.
	var isValid bool
	_, isValid = c.co.Server().PKI.AuthenticateReplicaConnection(creds)

	if !isValid {
		c.log.Debug("failed to authenticate connect via latest PKI doc")
	}
	return isValid
}

func (c *outgoingConn) dispatchMessage(mesg *commands.ReplicaMessage) {
	select {
	case c.ch <- mesg:
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
	var (
		// XXX NOTE(david): we might need to adjust these to be aligned with our pki worker thread
		retryIncrement = epochtime.Period / 64
		maxRetryDelay  = epochtime.Period / 8
	)

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
	return conn, false
}

func (c *outgoingConn) onConnEstablished(conn net.Conn, closeCh <-chan struct{}) (wasHalted bool) {
	defer func() {
		c.log.Debugf("TCP connection closed. (wasHalted: %v)", wasHalted)
		conn.Close()
	}()

	// Allocate the session struct.
	cfg := &wire.SessionConfig{
		KEMScheme:         c.linkScheme,
		Geometry:          c.cfg.SphinxGeometry,
		Authenticator:     c,
		AdditionalData:    []byte{},
		AuthenticationKey: c.co.Server().linkPrivKey,
		RandomReader:      rand.Reader,
	}
	envelopeScheme := nikeSchemes.ByName(c.cfg.EnvelopeScheme)
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

	// Start the peer reader.
	receiveCmdCh := make(chan interface{})
	c.Go(func() {
		defer close(receiveCmdCh)
		for {
			rawCmd, err := w.RecvCommand()
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				select {
				case <-c.HaltCh():
				case receiveCmdCh <- err:
				}
				return
			}

			c.log.Debugf("DEBUG: Received command from replica: %T", rawCmd)

			select {
			case <-c.HaltCh():
				return
			case receiveCmdCh <- rawCmd:
			}
		}
	})

	cmdCh := make(chan commands.Command)
	cmdCloseCh := make(chan error)
	defer close(cmdCh)
	go func() {
		defer close(cmdCloseCh)
		for {
			cmd, ok := <-cmdCh
			if !ok {
				return
			}
			if err := w.SendCommand(cmd); err != nil {
				c.log.Debugf("SendCommand failed: %v", err)
				return
			}
		}
	}()

	// Start the reauthenticate ticker.
	reauthMs := time.Duration(c.co.Server().cfg.ReauthInterval) * time.Millisecond
	reauth := time.NewTicker(reauthMs)
	defer reauth.Stop()

	for {
		var rawCmd commands.Command
		var cmd commands.Command
		select {
		case <-c.HaltCh():
			return
		case <-closeCh:
			wasHalted = true
			return
		case <-reauth.C:
			// Each outgoing connection has a periodic 1/15 Hz timer to wake up
			// and re-authenticate to handle the PKI document(s) changing.
			creds, err := w.PeerCredentials()
			if err != nil {
				c.log.Debugf("Session fail: %s", err)
				return
			}
			if !c.IsPeerValid(creds) {
				c.log.Debugf("Disconnecting, peer reauthenticate failed.")
				return
			}
			continue
		case cmd = <-c.ch:
			select {
			case <-c.HaltCh():
				return
			case <-closeCh:
				wasHalted = true
				return
			case cmdCh <- cmd:
			}
			continue
		case <-cmdCloseCh:
			// Something blew up when sending the command to the remote peer.
			return
		case replyCmd := <-receiveCmdCh:
			c.log.Debugf("DEBUG: Processing reply from receiveCmdCh: %T", replyCmd)
			switch cmdOrErr := replyCmd.(type) {
			case commands.Command:
				rawCmd = cmdOrErr
				c.log.Debugf("DEBUG: Got command from replica: %T", rawCmd)
			case error:
				c.log.Errorf("Received wire protocol RecvCommand error: %s", cmdOrErr)
			}
		}

		// Handle the response.
		c.log.Debugf("DEBUG: Handling response command: %T", rawCmd)
		switch replycmd := rawCmd.(type) {
		case *commands.NoOp:
			c.log.Debugf("Received NoOp.")
		case *commands.Disconnect:
			c.log.Debugf("Received Disconnect from peer.")
			return
		case *commands.ReplicaMessageReply:
			c.log.Debugf("DEBUG: Received ReplicaMessageReply - IsRead: %v, ErrorCode: %d, EnvelopeReplyLen: %d",
				replycmd.IsRead, replycmd.ErrorCode, len(replycmd.EnvelopeReply))
			c.courier.CacheReply(replycmd)
		default:
			c.log.Errorf("BUG, Received unexpected command from replica peer: %s", cmd)
			return
		}
	}
}

func newOutgoingConn(co GenericConnector, dst *cpki.ReplicaDescriptor, cfg *config.Config, courier *Courier) *outgoingConn {
	const maxQueueSize = 64 // TODO/perf: Tune this.

	linkScheme := kemSchemes.ByName(cfg.WireKEMScheme)
	idScheme := signSchemes.ByName(cfg.PKIScheme)
	envelopeScheme := nikeSchemes.ByName(cfg.EnvelopeScheme)

	c := &outgoingConn{
		linkScheme: linkScheme,
		cfg:        cfg,
		courier:    courier,
		co:         co,
		dst:        dst,
		ch:         make(chan *commands.ReplicaMessage, maxQueueSize),
		id:         atomic.AddUint64(&outgoingConnID, 1), // Diagnostic only, wrapping is fine.
	}
	c.log = co.Server().LogBackend().GetLogger(fmt.Sprintf("courier outgoing:%d", c.id))

	c.log.Debugf("New outgoing connection: %+v", dst.DisplayWithSchemes(linkScheme, idScheme, envelopeScheme))

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection map.

	return c
}
