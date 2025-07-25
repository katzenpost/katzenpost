// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"container/list"
	"crypto/hmac"
	"errors"
	"fmt"
	"net"
	"strings"
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
)

var incomingConnID uint64

type incomingConn struct {
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
	creds, blob, err := c.performHandshakeAndAuth(session)
	if err != nil {
		return
	}

	// Close old connections from the same peer
	if err := c.closeOldConnections(); err != nil {
		return
	}

	// Start command processing
	c.processCommands(session, creds, blob)
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
func (c *incomingConn) performHandshakeAndAuth(session *wire.Session) (*wire.PeerCredentials, []byte, error) {
	// Bind the session to the conn, handshake, authenticate.
	timeoutMs := time.Duration(c.l.server.cfg.HandshakeTimeout) * time.Millisecond
	c.c.SetDeadline(time.Now().Add(timeoutMs))
	if err := session.Initialize(c.c); err != nil {
		c.log.Errorf("Handshake failed: %v", err)
		return nil, nil, err
	}
	c.log.Debugf("Handshake completed.")
	c.c.SetDeadline(time.Time{})
	c.l.onInitializedConn(c)

	// Log the connection source.
	creds, err := session.PeerCredentials()
	if err != nil {
		c.log.Debugf("Session failure: %s", err)
		return nil, nil, err
	}
	blob, err := creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}

	return creds, blob, nil
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
func (c *incomingConn) processCommands(session *wire.Session, creds *wire.PeerCredentials, blob []byte) {
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
			c.log.Debugf("Failed to handle replica command: %v", rawCmd)
			return
		}

		// Send the response, if any.
		c.sendResponse(session, resp, blob)
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

// sendResponse sends a response command if one is provided
func (c *incomingConn) sendResponse(session *wire.Session, resp commands.Command, blob []byte) {
	if resp != nil {
		c.log.Debugf("Sending response: %T", resp)
		if err := session.SendCommand(resp); err != nil {
			c.log.Debugf("Peer %v: Failed to send response: %v", hash.Sum256(blob), err)
		} else {
			c.log.Debugf("Successfully sent response: %T", resp)
		}
	} else {
		c.log.Debugf("No response to send (resp is nil)")
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

	c.log.Warningf("replica/incoming: IsPeerValid(): Authentication failed, invalid AdditionalData length")
	c.log.Warningf("replica/incoming: IsPeerValid(): Remote Peer Credentials: ad_length=%d (expected: 0 or %d), link_key=%s",
		len(creds.AdditionalData), sConstants.NodeIDLength, strings.TrimSpace(pem.ToPublicPEMString(creds.PublicKey)))
	return false
}

// authenticateCourier handles authentication for courier connections
func (c *incomingConn) authenticateCourier(creds *wire.PeerCredentials) bool {
	doc := c.findPKIDocument()
	if doc == nil {
		c.log.Warningf("replica/incoming: authenticateCourier(): No PKI document available")
		c.log.Warningf("replica/incoming: authenticateCourier(): Remote Peer Credentials: link_key=%s",
			strings.TrimSpace(pem.ToPublicPEMString(creds.PublicKey)))
		return false
	}

	// Check if the public key matches any courier in the PKI document
	for _, desc := range doc.ServiceNodes {
		if desc.Kaetzchen == nil {
			continue
		}
		if c.validateCourierKey(desc, creds.PublicKey) {
			c.log.Debugf("replica/incoming: authenticateCourier(): Authenticated courier connection for '%s'", desc.Name)
			return true
		}
	}

	c.log.Warningf("replica/incoming: authenticateCourier(): Courier authentication failed")
	c.log.Warningf("replica/incoming: authenticateCourier(): Remote Peer Credentials: link_key=%s",
		strings.TrimSpace(pem.ToPublicPEMString(creds.PublicKey)))
	c.log.Warningf("replica/incoming: authenticateCourier(): Available service nodes with courier capability:")
	for _, desc := range doc.ServiceNodes {
		if desc.Kaetzchen != nil {
			rawLinkKey, err := desc.GetRawCourierLinkKey()
			if err == nil {
				c.log.Warningf("replica/incoming: authenticateCourier():   - name=%s, link_key=%s",
					desc.Name, strings.TrimSpace(rawLinkKey))
			}
		}
	}
	return false
}

// authenticateReplica handles authentication for replica connections
func (c *incomingConn) authenticateReplica(creds *wire.PeerCredentials) bool {
	var nodeID [sConstants.NodeIDLength]byte
	copy(nodeID[:], creds.AdditionalData)

	// Get replica descriptor from the replica map
	replicaDesc, isReplica := c.l.server.PKIWorker.replicas.GetReplicaDescriptor(&nodeID)
	if !isReplica {
		c.log.Warningf("replica/incoming: authenticateReplica(): Authentication failed: node ID %x not found in replica list", nodeID)
		c.log.Warningf("replica/incoming: authenticateReplica(): Remote Peer Credentials: node_id=%x, link_key=%s",
			nodeID, strings.TrimSpace(pem.ToPublicPEMString(creds.PublicKey)))

		// Log available replicas for debugging
		c.log.Warningf("replica/incoming: authenticateReplica(): Available replicas:")
		allReplicas := c.l.server.PKIWorker.replicas.Copy()
		for replicaID, replica := range allReplicas {
			c.log.Warningf("replica/incoming: authenticateReplica():   - name=%s, node_id=%x, link_key=%x",
				replica.Name, replicaID[:], replica.LinkKey)
		}
		return false
	}

	// Verify link key matches
	blob, err := creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if !hmac.Equal(replicaDesc.LinkKey, blob) {
		c.log.Warningf("replica/incoming: authenticateReplica(): Authentication failed: link key mismatch for replica '%s'", replicaDesc.Name)
		c.log.Warningf("replica/incoming: authenticateReplica(): Expected link key: %x", replicaDesc.LinkKey)
		c.log.Warningf("replica/incoming: authenticateReplica(): Received link key: %s",
			strings.TrimSpace(pem.ToPublicPEMString(creds.PublicKey)))
		c.log.Warningf("replica/incoming: authenticateReplica(): Remote Peer Credentials: name=%s, node_id=%x",
			replicaDesc.Name, nodeID)
		return false
	}

	c.log.Debugf("replica/incoming: authenticateReplica(): Authenticated replica connection for '%s'", replicaDesc.Name)
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
