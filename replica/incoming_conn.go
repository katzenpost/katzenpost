// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"container/list"
	"crypto/hmac"
	"fmt"
	"net"
	"net/url"
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
}

func (c *incomingConn) Close() {
	c.closeConnectionCh <- true
}

func (c *incomingConn) worker() {
	defer func() {
		c.log.Debugf("Closing.")
		c.c.Close()
		c.l.onClosedConn(c) // Remove from the connection list.
	}()

	// Check for bidirectional connection race condition BEFORE handshake
	// Get the remote address to see if we're already connecting to this peer
	remoteAddr := c.c.RemoteAddr().String()
	c.log.Debugf("Incoming connection from: %s", remoteAddr)

	// Extract the IP and port from the remote address
	// Skip bidirectional race detection for non-network connections (like pipes in tests)
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		c.log.Debugf("Cannot parse remote address %s (likely test connection): %v", remoteAddr, err)
		// Continue with normal handshake for test connections
	} else {
		// Check if we have any outgoing connections to the same host
		// This is a simple heuristic to detect bidirectional connection attempts
		myIdentityHash := hash.Sum256From(c.l.server.identityPublicKey)

		// For now, let's use a simple approach: if our ID is lower, we close incoming connections
		// and keep outgoing connections. This should prevent the deadlock.
		replicas := c.l.server.PKIWorker.ReplicasCopy()
		for nodeID, desc := range replicas {
			// Check if this replica has an address matching the incoming connection
			for _, addrs := range desc.Addresses {
				for _, addr := range addrs {
					if u, err := url.Parse(addr); err == nil {
						if addrHost, _, err := net.SplitHostPort(u.Host); err == nil {
							if addrHost == host {
								// This is a connection from a known replica
								if bytes.Compare(myIdentityHash[:], nodeID[:]) < 0 {
									c.log.Debugf("Closing incoming connection from %x due to bidirectional race - keeping outgoing connection", nodeID)
									return
								}
							}
						}
					}
				}
			}
		}
	}

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
	c.l.Lock()

	nikeScheme := nikeschemes.ByName(c.l.server.cfg.ReplicaNIKEScheme)
	c.w, err = wire.NewBidirectionalStorageReplicaSession(cfg, nikeScheme, false)

	c.l.Unlock()
	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		return
	}
	defer c.w.Close()

	// Bind the session to the conn, handshake, authenticate.
	timeoutMs := time.Duration(c.l.server.cfg.HandshakeTimeout) * time.Millisecond
	c.c.SetDeadline(time.Now().Add(timeoutMs))
	if err = c.w.Initialize(c.c); err != nil {
		c.log.Errorf("Handshake failed: %v", err)
		return
	}
	c.log.Debugf("Handshake completed.")
	c.c.SetDeadline(time.Time{})

	// Check for bidirectional connection race condition
	// If we have an outgoing connection to the same peer, close this incoming connection
	// to prevent protocol deadlocks
	creds, err := c.w.PeerCredentials()
	if err == nil && len(creds.AdditionalData) == sConstants.NodeIDLength {
		var peerNodeID [sConstants.NodeIDLength]byte
		copy(peerNodeID[:], creds.AdditionalData)

		// Check if we have an outgoing connection to this peer
		if c.l.server.connector.HasConnection(&peerNodeID) {
			myIdentityHash := hash.Sum256From(c.l.server.identityPublicKey)

			// Use deterministic rule: replica with lower ID keeps outgoing connection
			if bytes.Compare(myIdentityHash[:], peerNodeID[:]) < 0 {
				c.log.Debugf("Closing incoming connection due to bidirectional race - keeping outgoing connection to %x", peerNodeID)
				return
			} else {
				c.log.Debugf("Accepting incoming connection and will close outgoing connection to %x", peerNodeID)
				// Close the outgoing connection since we have higher ID
				c.l.server.connector.CloseConnection(&peerNodeID)
			}
		}
	}

	c.l.onInitializedConn(c)

	// Log the connection source.
	creds2, err := c.w.PeerCredentials()
	if err != nil {
		c.log.Debugf("Session failure: %s", err)
	}
	blob, err := creds2.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// Ensure that there's only one incoming conn from any given peer, though
	// this only really matters for user sessions. Newest connection wins.
	for _, s := range c.l.server.listeners {
		err := s.CloseOldConns(c)
		if err != nil {
			c.log.Errorf("Closing new connection because something is broken: " + err.Error())
			return
		}
	}

	// Start the reauthenticate ticker.
	reauthMs := time.Duration(c.l.server.cfg.ReauthInterval) * time.Millisecond
	reauth := time.NewTicker(reauthMs)
	defer reauth.Stop()

	// Start reading from the peer.
	commandCh := make(chan commands.Command)
	commandCloseCh := make(chan interface{})
	defer close(commandCloseCh)
	go func() {
		defer close(commandCh)
		for {
			rawCmd, err := c.w.RecvCommand()
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				return
			}
			select {
			case commandCh <- rawCmd:
			case <-commandCloseCh:
				// c.worker() is returning for some reason, give up on
				// trying to write the command, and just return.
				return
			}
		}
	}()

	// Process incoming packets.
	for {
		var rawCmd commands.Command
		var ok bool

		select {
		case <-c.l.closeAllCh:
			// Server is getting shutdown, all connections are being closed.
			return
		case <-reauth.C:
			// Each incoming conn has a periodic 1/15 Hz timer to wake up
			// and re-authenticate the connection to handle the PKI document(s)
			// and or the user database changing.
			//
			// Doing it this way avoids a good amount of complexity at the
			// the cost of extra authenticates (which should be fairly fast).
			if !c.IsPeerValid(creds) {
				c.log.Debugf("Disconnecting, peer reauthenticate failed.")
				return
			}
			continue
		case <-c.closeConnectionCh:
			c.log.Debugf("Disconnecting to make room for a newer connection from the same peer.")
			return
		case rawCmd, ok = <-commandCh:
			if !ok {
				return
			}
		}

		// Handle all of the storage replica commands.
		resp, allGood := c.onReplicaCommand(rawCmd)
		if !allGood {
			c.log.Debugf("Failed to handle replica command: %v", rawCmd)
			// Catastrophic failure in command processing, or a disconnect.
			return
		}

		// Send the response, if any.
		if resp != nil {
			c.log.Debugf("Sending response: %T", resp)
			if err = c.w.SendCommand(resp); err != nil {
				c.log.Debugf("Peer %v: Failed to send response: %v", hash.Sum256(blob), err)
			} else {
				c.log.Debugf("Successfully sent response: %T", resp)
			}
		} else {
			c.log.Debugf("No response to send (resp is nil)")
		}
	}

	// NOTREACHED
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
	c.log.Debugf("IsPeerValid: ENTRY - Starting peer validation from %s", c.c.RemoteAddr())

	if creds == nil {
		c.log.Errorf("IsPeerValid: creds is nil - RETURNING FALSE")
		return false
	}

	c.log.Debugf("IsPeerValid: AdditionalData length: %d, hex: %x", len(creds.AdditionalData), creds.AdditionalData)

	// Check if this is a courier connection (empty AdditionalData)
	if len(creds.AdditionalData) == 0 {
		c.log.Debugf("IsPeerValid: Detected courier connection (empty AdditionalData)")
		// Check courier authentication
		epoch, _, _ := epochtime.Now()
		c.log.Debugf("IsPeerValid: Current epoch: %d", epoch)

		// Try current, next, and previous epochs
		c.log.Debugf("IsPeerValid: Looking for PKI document for epoch %d", epoch)
		doc := c.l.server.PKIWorker.documentForEpoch(epoch)
		if doc == nil {
			c.log.Debugf("IsPeerValid: No doc for epoch %d, trying epoch %d", epoch, epoch+1)
			doc = c.l.server.PKIWorker.documentForEpoch(epoch + 1)
			if doc == nil {
				c.log.Debugf("IsPeerValid: No doc for epoch %d, trying epoch %d", epoch+1, epoch-1)
				doc = c.l.server.PKIWorker.documentForEpoch(epoch - 1)
				if doc == nil {
					c.log.Errorf("IsPeerValid: No PKI docs available for epochs %d, %d, or %d - RETURNING FALSE", epoch-1, epoch, epoch+1)
					return false
				}
			}
		}

		c.log.Debugf("IsPeerValid: Found PKI document for epoch %d with %d service nodes", doc.Epoch, len(doc.ServiceNodes))

		// Check if the public key matches any courier in the PKI document
		courierCount := 0
		for i, desc := range doc.ServiceNodes {
			if desc.Kaetzchen == nil {
				c.log.Debugf("IsPeerValid: ServiceNode[%d] %s has no Kaetzchen, skipping", i, desc.Name)
				continue
			}
			courierCount++
			c.log.Debugf("IsPeerValid: Checking ServiceNode[%d] %s (courier %d)", i, desc.Name, courierCount)

			rawLinkPubKey, err := desc.GetRawCourierLinkKey()
			if err != nil {
				c.log.Errorf("IsPeerValid: desc.GetRawCourierLinkKey() failure for %s: %s", desc.Name, err)
				continue
			}
			linkScheme := kemschemes.ByName(c.l.server.cfg.WireKEMScheme)
			linkPubKey, err := pem.FromPublicPEMString(rawLinkPubKey, linkScheme)
			if err != nil {
				c.log.Errorf("IsPeerValid: Failed to unmarshal courier link key for %s: %s", desc.Name, err)
				continue
			}
			if creds.PublicKey.Equal(linkPubKey) {
				c.log.Debugf("IsPeerValid: Authenticated courier connection for %s - RETURNING TRUE", desc.Name)
				return true
			}
			c.log.Debugf("IsPeerValid: Public key mismatch for courier %s", desc.Name)
		}
		c.log.Debugf("IsPeerValid: Courier authentication failed - checked %d couriers - RETURNING FALSE", courierCount)
		return false
	}

	// Check if this is a replica connection (AdditionalData is node ID hash)
	if len(creds.AdditionalData) == sConstants.NodeIDLength {
		c.log.Debugf("IsPeerValid: Detected replica connection (AdditionalData length: %d)", sConstants.NodeIDLength)
		var nodeID [sConstants.NodeIDLength]byte
		copy(nodeID[:], creds.AdditionalData)
		c.log.Debugf("IsPeerValid: Replica nodeID from AdditionalData: %x", nodeID)

		// Get replica descriptor from the replica map
		c.log.Debugf("IsPeerValid: Looking up replica descriptor for nodeID: %x", nodeID)
		replicaDesc, isReplica := c.l.server.PKIWorker.replicas.GetReplicaDescriptor(&nodeID)
		if !isReplica {
			c.log.Errorf("IsPeerValid: Authentication failed: node ID %x not found in replica list - RETURNING FALSE", nodeID)
			return false
		}
		c.log.Debugf("IsPeerValid: Found replica descriptor for nodeID: %x", nodeID)

		// Verify link key matches
		c.log.Debugf("IsPeerValid: Verifying link key for replica %x", nodeID)
		blob, err := creds.PublicKey.MarshalBinary()
		if err != nil {
			c.log.Errorf("IsPeerValid: Failed to marshal public key: %v", err)
			panic(err)
		}
		c.log.Debugf("IsPeerValid: Marshaled public key length: %d", len(blob))
		c.log.Debugf("IsPeerValid: Expected link key length: %d", len(replicaDesc.LinkKey))

		if !hmac.Equal(replicaDesc.LinkKey, blob) {
			c.log.Errorf("IsPeerValid: Authentication failed: link key mismatch for replica %x - RETURNING FALSE", nodeID)
			c.log.Debugf("IsPeerValid: Expected link key: %x", replicaDesc.LinkKey[:32]) // Show first 32 bytes
			c.log.Debugf("IsPeerValid: Received link key: %x", blob[:32])                // Show first 32 bytes
			return false
		}

		c.log.Debugf("IsPeerValid: Authenticated replica connection for nodeID %x - RETURNING TRUE", nodeID)
		return true
	}

	c.log.Errorf("IsPeerValid: Authentication failed, invalid AdditionalData length: %d (expected 0 or %d) - RETURNING FALSE",
		len(creds.AdditionalData), sConstants.NodeIDLength)
	return false
}
