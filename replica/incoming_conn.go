// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"container/list"
	"crypto/hmac"
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
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

var incomingConnID uint64

const (
	replicaMessageReplyDecapsulationFailure = 123
	replicaMessageReplyCommandParseFailure  = 122
)

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

	session, err := c.setupSession()
	if err != nil {
		c.log.Errorf("Failed to setup session: %v", err)
		return
	}
	defer session.Close()

	creds, blob, err := c.performHandshake(session)
	if err != nil {
		c.log.Errorf("Handshake failed: %v", err)
		return
	}

	if err := c.closeOldConnections(); err != nil {
		c.log.Errorf("Closing new connection because something is broken: " + err.Error())
		return
	}

	c.processCommands(session, creds, blob)
}

// setupSession creates and configures a new storage replica session
func (c *incomingConn) setupSession() (*wire.Session, error) {
	identityHash := hash.Sum256From(c.l.server.identityPublicKey)
	cfg := &wire.SessionConfig{
		KEMScheme:         c.scheme,
		Geometry:          c.geo,
		Authenticator:     c,
		AdditionalData:    identityHash[:],
		AuthenticationKey: c.l.server.linkKey,
		RandomReader:      rand.Reader,
	}

	c.l.Lock()
	nikeScheme := nikeschemes.ByName(c.l.server.cfg.ReplicaNIKEScheme)
	session, err := wire.NewStorageReplicaSession(cfg, nikeScheme, false)
	c.l.Unlock()

	if err != nil {
		return nil, err
	}

	c.setSession(session)
	return session, nil
}

// performHandshake handles the connection handshake and authentication
func (c *incomingConn) performHandshake(session *wire.Session) (*wire.PeerCredentials, []byte, error) {
	timeoutMs := time.Duration(c.l.server.cfg.HandshakeTimeout) * time.Millisecond
	c.c.SetDeadline(time.Now().Add(timeoutMs))

	if err := session.Initialize(c.c); err != nil {
		return nil, nil, err
	}

	c.log.Debugf("Handshake completed.")
	c.c.SetDeadline(time.Time{})
	c.l.onInitializedConn(c)

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
	for _, s := range c.l.server.listeners {
		if err := s.CloseOldConns(c); err != nil {
			return err
		}
	}
	return nil
}

// processCommands handles the main command processing loop
func (c *incomingConn) processCommands(session *wire.Session, creds *wire.PeerCredentials, blob []byte) {
	reauthMs := time.Duration(c.l.server.cfg.ReauthInterval) * time.Millisecond
	reauth := time.NewTicker(reauthMs)
	defer reauth.Stop()

	commandCh := make(chan commands.Command)
	commandCloseCh := make(chan interface{})
	defer close(commandCloseCh)

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
				// c.processCommands() is returning for some reason, give up on
				// trying to write the command, and just return.
				return
			}
		}
	}()

	for {
		rawCmd, shouldContinue := c.waitForCommand(commandCh, reauth, creds)
		if !shouldContinue {
			return
		}

		if rawCmd == nil {
			continue // Reauthentication case
		}

		c.handleCommand(session, rawCmd, blob)
	}
}

// waitForCommand waits for the next command or control signal
func (c *incomingConn) waitForCommand(commandCh chan commands.Command, reauth *time.Ticker, creds *wire.PeerCredentials) (commands.Command, bool) {
	select {
	case <-c.l.closeAllCh:
		return nil, false
	case <-reauth.C:
		if !c.IsPeerValid(creds) {
			c.log.Debugf("Disconnecting, peer reauthenticate failed.")
			return nil, false
		}
		return nil, true // Continue but skip command processing
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

// handleCommand processes a single command and sends the response
func (c *incomingConn) handleCommand(session *wire.Session, rawCmd commands.Command, blob []byte) {
	resp, allGood := c.onReplicaCommand(rawCmd)
	if !allGood {
		c.log.Debugf("Failed to handle replica command: %v", rawCmd)
		return
	}

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
		// Check courier authentication
		epoch, _, _ := epochtime.Now()

		// Try current, next, and previous epochs
		doc := c.l.server.PKIWorker.documentForEpoch(epoch)
		if doc == nil {
			doc = c.l.server.PKIWorker.documentForEpoch(epoch + 1)
			if doc == nil {
				doc = c.l.server.PKIWorker.documentForEpoch(epoch - 1)
				if doc == nil {
					c.log.Errorf("No PKI docs available for epochs %d, %d, or %d", epoch-1, epoch, epoch+1)
					return false
				}
			}
		}

		// Check if the public key matches any courier in the PKI document
		for _, desc := range doc.ServiceNodes {
			if desc.Kaetzchen == nil {
				continue
			}
			rawLinkPubKey, err := desc.GetRawCourierLinkKey()
			if err != nil {
				c.log.Errorf("desc.GetRawCourierLinkKey() failure: %s", err)
				continue
			}
			linkScheme := kemschemes.ByName(c.l.server.cfg.WireKEMScheme)
			linkPubKey, err := pem.FromPublicPEMString(rawLinkPubKey, linkScheme)
			if err != nil {
				c.log.Errorf("Failed to unmarshal courier link key: %s", err)
				continue
			}
			if creds.PublicKey.Equal(linkPubKey) {
				c.log.Debug("IncomingConn: Authenticated courier connection")
				return true
			}
		}
		c.log.Debug("IncomingConn: Courier authentication failed")
		return false
	}

	// Check if this is a replica connection (AdditionalData is node ID hash)
	if len(creds.AdditionalData) == sConstants.NodeIDLength {
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

	c.log.Debug("IncomingConn: Authentication failed, invalid AdditionalData length")
	return false
}
