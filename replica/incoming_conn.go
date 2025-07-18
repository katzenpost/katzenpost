// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"container/list"
	"crypto/hmac"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/worker"
)

var incomingConnID uint64

type incomingConn struct {
	worker.Worker

	scheme        kem.Scheme
	pkiSignScheme sign.Scheme

	l   *Listener
	log *logging.Logger

	c   net.Conn
	e   *list.Element
	w   wire.SessionInterface
	geo *geo.Geometry

	id      uint64
	retrSeq uint32

	isInitialized bool // Set by listener.

	closeConnectionCh chan bool

	// Mutex to protect session access
	sessionMutex sync.RWMutex
}

func (c *incomingConn) Close() {
	c.closeConnectionCh <- true
}

// getSession safely gets the session with read lock
func (c *incomingConn) getSession() wire.SessionInterface {
	c.sessionMutex.RLock()
	defer c.sessionMutex.RUnlock()
	return c.w
}

// setSession safely sets the session with write lock
func (c *incomingConn) setSession(session wire.SessionInterface) {
	c.sessionMutex.Lock()
	defer c.sessionMutex.Unlock()
	c.w = session
}

func (c *incomingConn) worker() {
	defer func() {
		c.log.Debugf("Closing.")
		c.c.Close()
		c.l.onClosedConn(c) // Remove from the connection list.
	}()

	// Initialize session
	session, err := c.initializeSession()
	if err != nil {
		return
	}
	defer session.Close()

	// Perform handshake and authentication
	creds, err := c.performHandshakeAndAuth(session)
	if err != nil {
		return
	}

	// Close old connections from the same peer
	if err := c.closeOldConnections(); err != nil {
		return
	}

	// Constant time message output whether or not decoy traffic
	// is enabled.
	inCh := make(chan *senderRequest, 100)
	outCh := make(chan *senderRequest)
	nikeScheme := nikeschemes.ByName(c.l.server.cfg.ReplicaNIKEScheme)
	cmds := commands.NewStorageReplicaCommands(c.geo, nikeScheme)
	sender := newSender(inCh, outCh, c.l.server.cfg.DisableDecoyTraffic, c.l.server.logBackend, cmds)
	sender.UpdateConnectionStatus(true)
	doc := c.l.server.PKIWorker.PKIDocument()
	if doc == nil {
		c.log.Errorf("Failed to get PKI document")
		return
	}
	// XXX FIXME(David): add a new lamda parameter to our pki doc format, lambdaR.
	// for now use lambdaP
	// LambdaP is the inverse of the rate, so rate = 1/LambdaP
	rate := uint64(1.0 / doc.LambdaP)
	if rate == 0 {
		rate = 1 // Minimum rate of 1 message per time unit
	}
	maxDelay := doc.LambdaPMaxDelay
	sender.UpdateRate(rate, maxDelay)

	// Start command processing
	c.Go(func() {
		defer sender.UpdateConnectionStatus(false) // Mark as disconnected when command processing stops
		c.processCommands(session, creds, inCh)
	})
	c.Go(func() {
		c.egressSender(session, outCh)
	})

	// Halt sender first to stop generating messages
	sender.Halt()
	sender.Wait()

	// Then wait for the connection workers to finish
	c.Wait()
}

func (c *incomingConn) egressSender(session *wire.Session, outCh chan *senderRequest) {
	for {
		select {
		case <-c.HaltCh():
			return
		case resp := <-outCh:
			c.sendResponse(session, resp)
		}
	}
}

// sendResponse sends a response command if one is provided
func (c *incomingConn) sendResponse(session *wire.Session, resp *senderRequest) {
	if resp != nil {
		cmd := resp.command()
		if cmd == nil {
			c.log.Debugf("Failed to send response: nil command")
			return
		}
		if err := session.SendCommand(cmd); err != nil {
			// Only log as debug since this is expected when connections close
			c.log.Debugf("Failed to send response: %v", err)
		}
	} else {
		c.log.Debugf("No response to send (resp is nil)")
	}
}

// initializeSession creates and configures the wire session
func (c *incomingConn) initializeSession() (*wire.Session, error) {
	// Allocate the session struct.
	identityHash := hash.Sum256From(c.l.server.identityPublicKey)
	cfg := &wire.SessionConfig{
		KEMScheme:         c.scheme,
		Geometry:          c.geo,
		Authenticator:     c,
		AdditionalData:    identityHash[:],
		AuthenticationKey: c.l.server.linkKey,
		RandomReader:      rand.Reader,
	}
	var err error
	c.l.Lock()

	nikeScheme := nikeschemes.ByName(c.l.server.cfg.ReplicaNIKEScheme)
	session, err := wire.NewStorageReplicaSession(cfg, nikeScheme, false)

	c.l.Unlock()

	if err == nil {
		c.setSession(session)
	}

	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		return nil, err
	}

	sessionInterface := c.getSession()
	if sessionInterface == nil {
		c.log.Errorf("Failed to get session")
		return nil, errors.New("failed to get session")
	}
	session, ok := sessionInterface.(*wire.Session)
	if !ok {
		c.log.Errorf("Failed to cast session to *wire.Session")
		return nil, errors.New("failed to cast session to *wire.Session")
	}

	return session, nil
}

// performHandshakeAndAuth handles the handshake and authentication process
func (c *incomingConn) performHandshakeAndAuth(session *wire.Session) (*wire.PeerCredentials, error) {
	timeoutMs := time.Duration(c.l.server.cfg.HandshakeTimeout) * time.Millisecond
	c.c.SetDeadline(time.Now().Add(timeoutMs))
	if err := session.Initialize(c.c); err != nil {
		c.log.Errorf("Handshake failed: %v", err)
		return nil, err
	}
	c.log.Debugf("Handshake completed.")
	c.c.SetDeadline(time.Time{})
	c.l.onInitializedConn(c)
	creds, err := session.PeerCredentials()
	if err != nil {
		c.log.Debugf("Session failure: %s", err)
		return nil, err
	}
	return creds, nil
}

// closeOldConnections ensures only one connection per peer
func (c *incomingConn) closeOldConnections() error {
	// Ensure that there's only one incoming conn from any given peer, though
	// this only really matters for user sessions. Newest connection wins.
	for _, s := range c.l.server.listeners {
		err := s.CloseOldConns(c)
		if err != nil {
			c.log.Errorf("Closing new connection because something is broken: " + err.Error())
			return err
		}
	}
	return nil
}

// processCommands handles the main command processing loop
func (c *incomingConn) processCommands(session *wire.Session, creds *wire.PeerCredentials, inCh chan *senderRequest) {
	// Start the reauthenticate ticker.
	reauthMs := time.Duration(c.l.server.cfg.ReauthInterval) * time.Millisecond
	reauth := time.NewTicker(reauthMs)
	defer reauth.Stop()

	// Start reading from the peer.
	commandCh, commandCloseCh := c.startCommandReader(session)
	defer close(commandCloseCh)

	// Process incoming packets.
	for {
		rawCmd, shouldContinue := c.handleSelectCases(reauth.C, creds, commandCh)
		if !shouldContinue {
			return
		}
		if rawCmd == nil {
			continue
		}

		// Handle all of the storage replica commands.
		resp, allGood := c.onReplicaCommand(rawCmd)
		if !allGood {
			c.log.Debugf("Got a disconnect or we failed to handle replica command: %v", rawCmd)
			return
		}

		inCh <- resp
	}
}

// startCommandReader starts a goroutine to read commands from the session
func (c *incomingConn) startCommandReader(session *wire.Session) (chan commands.Command, chan any) {
	commandCh := make(chan commands.Command)
	commandCloseCh := make(chan any)

	go func() {
		defer close(commandCh)
		for {
			rawCmd, err := session.RecvCommand()
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				return
			}
			select {
			case commandCh <- rawCmd:
			case <-commandCloseCh:
				return
			}
		}
	}()

	return commandCh, commandCloseCh
}

// handleSelectCases handles the main select statement cases
func (c *incomingConn) handleSelectCases(reauthCh <-chan time.Time, creds *wire.PeerCredentials, commandCh <-chan commands.Command) (commands.Command, bool) {
	select {
	case <-c.l.closeAllCh:
		return nil, false
	case <-reauthCh:
		if !c.IsPeerValid(creds) {
			c.log.Debugf("Disconnecting, peer reauthenticate failed.")
			return nil, false
		}
		return nil, true
	case <-c.closeConnectionCh:
		c.log.Debugf("Disconnecting to make room for a newer connection from the same peer.")
		return nil, false
	case rawCmd, ok := <-commandCh:
		if !ok {
			return nil, false
		}
		return rawCmd, true
	}
}

func newIncomingConn(l *Listener, conn net.Conn, geo *geo.Geometry, scheme kem.Scheme, pkiSignScheme sign.Scheme) *incomingConn {
	c := &incomingConn{
		scheme:            scheme,
		pkiSignScheme:     pkiSignScheme,
		l:                 l,
		c:                 conn,
		id:                atomic.AddUint64(&incomingConnID, 1), // Diagnostic only, wrapping is fine.
		closeConnectionCh: make(chan bool),
		geo:               geo,
	}
	c.log = l.server.logBackend.GetLogger(fmt.Sprintf("replica incoming:%d", c.id))
	c.log.Debugf("New incoming connection: %v", conn.RemoteAddr())

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection list.

	return c
}

func (c *incomingConn) IsPeerValid(creds *wire.PeerCredentials) bool {
	// Check if this is a courier connection (empty AdditionalData)
	if len(creds.AdditionalData) == 0 {
		return c.authenticateCourier(creds)
	}

	// Check if this is a replica connection (AdditionalData is node ID hash)
	if len(creds.AdditionalData) == sConstants.NodeIDLength {
		return c.authenticateReplica(creds)
	}

	c.log.Debug("IncomingConn: Authentication failed, invalid AdditionalData length")
	return false
}

// authenticateCourier handles authentication for courier connections
func (c *incomingConn) authenticateCourier(creds *wire.PeerCredentials) bool {
	doc := c.findPKIDocument()
	if doc == nil {
		return false
	}

	// Check if the public key matches any courier in the PKI document
	for _, desc := range doc.ServiceNodes {
		if desc.Kaetzchen == nil {
			continue
		}
		if c.validateCourierKey(desc, creds.PublicKey) {
			c.log.Debug("IncomingConn: Authenticated courier connection")
			return true
		}
	}
	c.log.Debug("IncomingConn: Courier authentication failed")
	return false
}

// authenticateReplica handles authentication for replica connections
func (c *incomingConn) authenticateReplica(creds *wire.PeerCredentials) bool {
	var nodeID [sConstants.NodeIDLength]byte
	copy(nodeID[:], creds.AdditionalData)

	// Get replica descriptor from the replica map
	replicaDesc, isReplica := c.l.server.PKIWorker.replicas.GetReplicaDescriptor(&nodeID)
	if !isReplica {
		c.log.Debugf("Authentication failed: node ID %x not found in replica list", nodeID)
		return false
	}

	// Verify link key matches
	blob, err := creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if !hmac.Equal(replicaDesc.LinkKey, blob) {
		c.log.Debugf("Authentication failed: link key mismatch for replica %x", nodeID)
		return false
	}

	c.log.Debug("IncomingConn: Authenticated replica connection")
	return true
}

// findPKIDocument finds a PKI document for current, next, or previous epoch
func (c *incomingConn) findPKIDocument() *pki.Document {
	epoch, _, _ := epochtime.Now()

	// Try current, next, and previous epochs
	doc := c.l.server.PKIWorker.documentForEpoch(epoch)
	if doc == nil {
		doc = c.l.server.PKIWorker.documentForEpoch(epoch + 1)
		if doc == nil {
			doc = c.l.server.PKIWorker.documentForEpoch(epoch - 1)
			if doc == nil {
				c.log.Errorf("No PKI docs available for epochs %d, %d, or %d", epoch-1, epoch, epoch+1)
				return nil
			}
		}
	}
	return doc
}

// validateCourierKey validates a courier's link key against the provided public key
func (c *incomingConn) validateCourierKey(desc *pki.MixDescriptor, publicKey kem.PublicKey) bool {
	rawLinkPubKey, err := desc.GetRawCourierLinkKey()
	if err != nil {
		c.log.Errorf("desc.GetRawCourierLinkKey() failure: %s", err)
		return false
	}
	linkScheme := kemschemes.ByName(c.l.server.cfg.WireKEMScheme)
	linkPubKey, err := pem.FromPublicPEMString(rawLinkPubKey, linkScheme)
	if err != nil {
		c.log.Errorf("Failed to unmarshal courier link key: %s", err)
		return false
	}
	return publicKey.Equal(linkPubKey)
}
