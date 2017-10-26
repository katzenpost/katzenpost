// incoming_conn.go - Katzenpost server incoming connection handler.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package server

import (
	"container/list"
	"fmt"
	"math"
	"net"
	"sync/atomic"
	"time"

	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/monotime"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/wire/commands"
	"github.com/op/go-logging"
)

var incomingConnID uint64

type incomingConn struct {
	s   *Server
	l   *listener
	c   net.Conn
	e   *list.Element
	w   *wire.Session
	log *logging.Logger

	id            uint64
	retrSeq       uint32
	isInitialized bool // Set by listener.
	fromClient    bool
	fromMix       bool
	canSend       bool
}

func (c *incomingConn) IsPeerValid(creds *wire.PeerCredentials) bool {
	if c.s.provider != nil && !c.fromMix {
		isClient := c.s.provider.authenticateClient(creds)
		if !isClient && c.fromClient {
			// This used to be a client, but is no longer listed in
			// the user db.  Reject.
			c.canSend = false
			return false
		} else if isClient {
			// Ok this is a connection from a client.
			c.fromClient = true
			c.canSend = true // Clients can always send for now.
			return true
		}

		// Connection is not from a client, so see if it's a mix.
	}

	// Well, the peer has to be a mix since we're not a provider, or the user
	// is unknown.
	c.fromClient = false
	isValid := false
	c.canSend, isValid = c.s.pki.authenticateIncoming(creds)
	if isValid {
		c.fromMix = true
	}
	c.log.Debugf("Authenticate Peer: '%v' (%v): %v", bytesToPrintString(creds.AdditionalData), creds.PublicKey, isValid)
	return isValid
}

func (c *incomingConn) worker() {
	defer func() {
		c.log.Debugf("Closing.")
		c.c.Close()
		c.l.onClosedConn(c) // Remove from the connection list.
	}()

	// Allocate the session struct.
	cfg := &wire.SessionConfig{
		Authenticator:     c,
		AdditionalData:    c.s.identityKey.PublicKey().Bytes(),
		AuthenticationKey: c.s.linkKey,
		RandomReader:      rand.Reader,
	}
	var err error
	c.w, err = wire.NewSession(cfg, false)
	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		return
	}
	defer c.w.Close()

	// Bind the session to the conn, handshake, authenticate.
	timeoutMs := time.Duration(c.s.cfg.Debug.HandshakeTimeout) * time.Millisecond
	c.c.SetDeadline(time.Now().Add(timeoutMs))
	if err = c.w.Initialize(c.c); err != nil {
		c.log.Errorf("Handshake failed: %v", err)
		return
	}
	c.log.Debugf("Handshake completed.")
	c.c.SetDeadline(time.Time{})
	c.l.onInitializedConn(c)

	// Ensure that there's only one incoming conn from any given peer, though
	// this only really matters for user sessions.  The easiest thing to do
	// is "oldest connection wins" since that doesn't require one connection
	// closing another.
	//
	// TODO: Newest connection wins is more annoying to implement, but better
	// behavior.
	for _, s := range c.s.listeners {
		if !s.isConnUnique(c) {
			c.log.Errorf("Connection with credentials already exists.")
			return
		}
	}

	// Start the reauthenticate ticker.
	reauthMs := time.Duration(c.s.cfg.Debug.ReauthInterval) * time.Millisecond
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
		ok := false

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
			if !c.IsPeerValid(c.w.PeerCredentials()) {
				c.log.Debugf("Disconnecting, peer reauthenticate failed.")
				return
			}
			continue
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

		if c.fromClient {
			// The only command specific to a client is RetreiveMessage.
			if retrCmd, ok := rawCmd.(*commands.RetrieveMessage); ok {
				if err := c.onRetrieveMessage(retrCmd); err != nil {
					c.log.Debugf("Failed to handle RetreiveMessage: %v", err)
					return
				}
				continue
			}
		}

		// Handle all of the common commands.
		if !c.onMixCommand(rawCmd) {
			// Catastrophic failure in command processing, or a disconnect.
			return
		}
	}

	// NOTREACHED
}

func (c *incomingConn) onMixCommand(rawCmd commands.Command) bool {
	switch cmd := rawCmd.(type) {
	case *commands.NoOp:
		c.log.Debugf("Received NoOp from peer.")
		return true
	case *commands.SendPacket:
		err := c.onSendPacket(cmd)
		if err == nil {
			return true
		}
		c.log.Debugf("Failed to handle SendPacket: %v", err)
	case *commands.Disconnect:
		c.log.Debugf("Received disconnect from peer.")
	default:
		c.log.Debugf("Received unexpected command: %t", cmd)
	}
	return false
}

func (c *incomingConn) onRetrieveMessage(cmd *commands.RetrieveMessage) error {
	advance := false
	switch cmd.Sequence {
	case c.retrSeq:
		c.log.Debugf("RetrieveMessage: %d", cmd.Sequence)
	case c.retrSeq + 1:
		c.log.Debugf("RetriveMessage: %d (Popping head)", cmd.Sequence)
		c.retrSeq++ // Advance the sequence number.
		advance = true
	default:
		return fmt.Errorf("provider: RetrieveMessage out of sequence: %d", cmd.Sequence)
	}

	// Get the message from the user's spool, advancing as appropriate.
	msg, surbID, remaining, err := c.s.provider.spool.Get(c.w.PeerCredentials().AdditionalData, advance)
	if err != nil {
		return err
	}
	if remaining > math.MaxUint8 {
		// The count hint is an 8 bit value and is clamped.
		remaining = math.MaxUint8
	}
	hint := uint8(remaining)

	var respCmd commands.Command
	if surbID != nil {
		// This was a SURBReply.
		surbCmd := &commands.MessageACK{
			QueueSizeHint: hint,
			Sequence:      cmd.Sequence,
			Payload:       msg,
		}
		copy(surbCmd.ID[:], surbID)
		respCmd = surbCmd

		if len(msg) != constants.ForwardPayloadLength {
			return fmt.Errorf("stored SURBReply payload is mis-sized: %v", len(msg))
		}
	} else if msg != nil {
		// This was a message.
		respCmd = &commands.Message{
			QueueSizeHint: hint,
			Sequence:      cmd.Sequence,
			Payload:       msg,
		}
		if len(msg) != constants.UserForwardPayloadLength {
			return fmt.Errorf("stored user payload is mis-sized: %v", len(msg))
		}
	} else {
		// Queue must be empty.
		if hint != 0 {
			panic("BUG: Get() failed to return a message, and the queue is not empty.")
		}
		respCmd = &commands.MessageEmpty{
			Sequence: cmd.Sequence,
		}
	}

	return c.w.SendCommand(respCmd)
}

func (c *incomingConn) onSendPacket(cmd *commands.SendPacket) error {
	pkt := newPacket()
	if err := pkt.copyToRaw(cmd.SphinxPacket); err != nil {
		return err
	}

	// Providers need to track packets received from other mixes vs
	// packets received from clients, avoid attempts by the final layer
	// to try to loop traffic back into the mix net, and sending packets
	// that bypass the mix net.
	pkt.mustForward = c.fromClient
	pkt.mustTerminate = c.s.cfg.Server.IsProvider && !c.fromClient

	// TODO: If clients should be rate-limited in how fast they can send
	// packets, this is probably the natural place to do so.

	c.log.Debugf("Handing off packet: %v", pkt.id)

	// For purposes of fudging the scheduling delay based on queue dwell
	// time, we treat the moment the packet is inserted into the crypto
	// worker queue as the time the packet was received.
	pkt.recvAt = monotime.Now()
	c.s.inboundPackets.In() <- pkt

	return nil
}

func newIncomingConn(l *listener, conn net.Conn) *incomingConn {
	c := new(incomingConn)
	c.s = l.s
	c.l = l
	c.c = conn
	c.id = atomic.AddUint64(&incomingConnID, 1) // Diagnostic only, wrapping is fine.
	c.log = l.s.logBackend.GetLogger(fmt.Sprintf("incoming:%d", c.id))

	c.log.Debugf("New incoming connection: %v", conn.RemoteAddr())

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection list.

	return c
}
