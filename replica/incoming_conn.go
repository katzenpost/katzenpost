// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"container/list"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/blake2b"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"

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
	w   *wire.Session
	geo *geo.Geometry

	id      uint64
	retrSeq uint32

	isInitialized bool // Set by listener.
	canSend       bool

	closeConnectionCh chan bool
}

func (c *incomingConn) IsPeerValid(creds *wire.PeerCredentials) bool {
	if c.l.server.pkiWorker.AuthenticateCourierConnection(creds) {
		return true
	}
	if _, isValid := c.l.server.pkiWorker.AuthenticateReplicaConnection(creds); isValid {
		return true
	}
	return false
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
		resp, allGood := c.onReplicaCommand(rawCmd)
		if !allGood {
			// Catastrophic failure in command processing, or a disconnect.
			return
		}

		// Send the response, if any.
		if resp != nil {
			if err = c.w.SendCommand(resp); err != nil {
				c.log.Debugf("Peer %v: Failed to send response: %v", hash.Sum256(blob), err)
			}
		}

	}

	// NOTREACHED
}

func (c *incomingConn) onReplicaCommand(rawCmd commands.Command) (commands.Command, bool) {
	switch cmd := rawCmd.(type) {
	case *commands.NoOp:
		c.log.Debugf("Received NoOp from peer.")
		return nil, true
	case *commands.Disconnect:
		c.log.Debugf("Received disconnect from peer.")
		return nil, false
	case *commands.ReplicaWrite:
		c.log.Debugf("Received ReplicaWrite from peer.")
		resp := c.handleReplicaWrite(cmd)
		return resp, true
	case *commands.ReplicaMessage:
		c.log.Debugf("Received ReplicaMessage from peer.")
		resp := c.handleReplicaMessage(cmd)
		return resp, true
	default:
		c.log.Debugf("Received unexpected command: %T", cmd)
		return nil, false
	}
	// not reached
}

func (c *incomingConn) handleReplicaMessage(replicaMessage *commands.ReplicaMessage) commands.Command {
	scheme := mkem.NewScheme()
	ct, err := mkem.CiphertextFromBytes(scheme, replicaMessage.Ciphertext)
	if err != nil {
		c.log.Errorf("handleReplicaMessage CiphertextFromBytes failed: %s", err)
		return nil
	}

	replicaEpoch, _, _ := ReplicaNow()
	replicaPrivateKeypair, err := c.l.server.envelopeKeys.GetKeypair(replicaEpoch)
	if err != nil {
		c.log.Errorf("handleReplicaMessage envelopeKeys.GetKeypair failed: %s", err)
		return nil
	}
	requestRaw, err := scheme.Decapsulate(replicaPrivateKeypair.PrivateKey, ct.Envelope)
	if err != nil {
		c.log.Errorf("handleReplicaMessage Decapsulate failed: %s", err)
		errReply := &commands.ReplicaMessageReply{
			ErrorCode: replicaMessageReplyDecapsulationFailure,
		}
		return errReply
	}
	cmds := commands.NewStorageReplicaCommands(c.l.server.cfg.SphinxGeometry)
	myCmd, err := cmds.FromBytes(requestRaw)
	if err != nil {
		c.log.Errorf("handleReplicaMessage Decapsulate failed: %s", err)
		errReply := &commands.ReplicaMessageReply{
			ErrorCode: replicaMessageReplyCommandParseFailure,
		}
		return errReply
	}
	switch myCmd := myCmd.(type) {
	case *commands.ReplicaRead:
		return c.handleReplicaRead(myCmd)
	case *commands.ReplicaWrite:
		defer c.doReplication(myCmd)
		return c.handleReplicaWrite(myCmd)
	default:
		c.log.Error("handleReplicaMessage failed: invalid request was decrypted")
		return nil
	}
}

func (c *incomingConn) handleReplicaRead(replicaRead *commands.ReplicaRead) *commands.ReplicaReadReply {
	const (
		successCode = 0
		failCode    = 1
	)
	resp, err := c.l.server.state.handleReplicaRead(replicaRead)
	if err != nil {
		return &commands.ReplicaReadReply{
			ErrorCode: failCode,
		}
	}
	return &commands.ReplicaReadReply{
		ErrorCode: successCode,
		BoxID:     resp.BoxID,
		Signature: resp.Signature,
		Payload:   resp.Payload,
	}
}

func (c *incomingConn) doReplication(cmd *commands.ReplicaWrite) {
	doc := c.l.server.pkiWorker.PKIDocument()
	descs, err := c.l.server.GetRemoteShards(cmd.BoxID, doc)
	if err != nil {
		c.log.Errorf("handleReplicaMessage failed: GetShards err: %x", err)
		panic(err)
	}
	for _, desc := range descs {
		idHash := blake2b.Sum256(desc.IdentityKey)
		c.l.server.connector.DispatchCommand(cmd, &idHash)
	}
}

func (c *incomingConn) handleReplicaWrite(replicaWrite *commands.ReplicaWrite) *commands.ReplicaWriteReply {
	const (
		successCode = 0
		failCode    = 1
	)
	err := c.l.server.state.handleReplicaWrite(replicaWrite)
	if err != nil {
		c.log.Errorf("handleReplicaWrite failed: %v", err)
		return &commands.ReplicaWriteReply{
			ErrorCode: failCode,
		}
	}
	return &commands.ReplicaWriteReply{
		ErrorCode: successCode,
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
