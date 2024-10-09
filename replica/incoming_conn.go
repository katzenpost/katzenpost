// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"container/list"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
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
	w   *wire.Session
	geo *geo.Geometry

	id      uint64
	retrSeq uint32

	isInitialized bool // Set by listener.
	fromClient    bool
	fromMix       bool
	canSend       bool

	closeConnectionCh chan bool
}

func (c *incomingConn) IsPeerValid(creds *wire.PeerCredentials) bool {
	_, err := creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// Ensure the additional data is valid.
	if len(creds.AdditionalData) != constants.NodeIDLength {
		c.log.Debugf("incoming: '%x' AD is not an IdentityKey hash", creds.AdditionalData)
		return false
	}
	var nodeID [constants.NodeIDLength]byte
	copy(nodeID[:], creds.AdditionalData)

	return true // XXX FIX ME
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

	c.w, err = wire.NewStorageReplicaSession(cfg, false)

	c.l.Unlock()
	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		return
	}
	defer c.w.Close()

	// Bind the session to the conn, handshake, authenticate.
	timeoutMs := time.Duration(30000 * time.Millisecond)
	c.c.SetDeadline(time.Now().Add(timeoutMs))
	if err = c.w.Initialize(c.c); err != nil {
		c.log.Errorf("Handshake failed: %v", err)
		return
	}
	c.log.Debugf("Handshake completed.")
	c.c.SetDeadline(time.Time{})
	c.l.onInitializedConn(c)

	// Log the connection source.
	creds, err := c.w.PeerCredentials()
	if err != nil {
		c.log.Debugf("Session failure: %s", err)
	}
	blob, err := creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if c.fromMix {
		c.log.Debugf("Peer: '%x' (%x)", creds.AdditionalData, hash.Sum256(blob))
	} else {
		c.log.Debugf("User: '%x', Key: '%x'", creds.AdditionalData, hash.Sum256(blob))
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
	reauthMs := time.Duration(30000 * time.Millisecond)
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

		// TODO: It's possible that a peer connects right at the tail end
		// before we start allowing "early" packets, resulting in c.canSend
		// being false till the reauth timer fires.  This probably isn't a
		// big deal since everyone should be using NTP anyway.
		if !c.canSend {
			// The peer's PKI document entry isn't for the current epoch,
			// or within the slack time.
			c.log.Debugf("Dropping mix command received out of epoch.")
			continue
		}

		// Handle all of the storage replica commands.
		if !c.onReplicaCommand(rawCmd) {
			// Catastrophic failure in command processing, or a disconnect.
			return
		}
	}

	// NOTREACHED
}

func (c *incomingConn) onReplicaCommand(rawCmd commands.Command) bool {
	switch cmd := rawCmd.(type) {
	case *commands.NoOp:
		c.log.Debugf("Received NoOp from peer.")
		return true
	case *commands.Disconnect:
		c.log.Debugf("Received disconnect from peer.")
	case *commands.ReplicaRead:
		c.log.Debugf("Received ReplicaRead from peer.")
		c.handleReplicaRead(cmd)
		return true
	case *commands.ReplicaWrite:
		c.log.Debugf("Received ReplicaWrite from peer.")
		c.handleReplicaWrite(cmd)
		return true
	case *commands.ReplicaMessage:
		c.log.Debugf("Received ReplicaMessage from peer.")
		c.handleReplicaMessage(cmd)
		return true

	default:
		c.log.Debugf("Received unexpected command: %T", cmd)
	}
	return false
}

func (c *incomingConn) handleReplicaMessage(replicaMessage *commands.ReplicaMessage) {
	scheme := mkem.NewScheme()
	ct, err := mkem.CiphertextFromBytes(scheme, replicaMessage.Ciphertext)
	if err != nil {
		c.log.Errorf("handleReplicaMessage CiphertextFromBytes failed: %s", err)
		return
	}
	requestRaw, err := scheme.Decapsulate(c.l.server.replicaPrivateKey, ct.Envelope)
	if err != nil {
		c.log.Errorf("handleReplicaMessage Decapsulate failed: %s", err)
		return
	}
	cmds := commands.NewStorageReplicaCommands(c.l.server.cfg.SphinxGeometry)
	myCmd, err := cmds.FromBytes(requestRaw)
	if err != nil {
		c.log.Errorf("handleReplicaMessage Decapsulate failed: %s", err)
		return
	}
	switch myCmd := myCmd.(type) {
	case *commands.ReplicaRead:
		c.handleReplicaRead(myCmd)
		return
	case *commands.ReplicaWrite:
		c.handleReplicaWrite(myCmd)
		return
	default:
		c.log.Error("handleReplicaMessage failed: invalid request was decrypted")
		return
	}
}

func (c *incomingConn) handleReplicaRead(replicaRead *commands.ReplicaRead) {
	// XXX FIX ME
	_, err := c.l.server.state.handleReplicaRead(replicaRead)
	if err != nil {
		panic(err) // XXX
	}
}

func (c *incomingConn) handleReplicaWrite(replicaWrite *commands.ReplicaWrite) {
	// XXX FIX ME
	err := c.l.server.state.handleReplicaWrite(replicaWrite)
	if err != nil {
		panic(err) // XXX
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
	c.log = l.server.logBackend.GetLogger(fmt.Sprintf("incoming:%d", c.id))
	c.log.Debugf("New incoming connection: %v", conn.RemoteAddr())

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection list.

	return c
}
