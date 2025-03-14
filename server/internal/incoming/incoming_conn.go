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

package incoming

import (
	"container/list"
	"fmt"
	"math"
	"net"
	"sync/atomic"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"

	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

var incomingConnID uint64

type incomingConn struct {
	scheme        kem.Scheme
	pkiSignScheme sign.Scheme

	l   *listener
	log *logging.Logger

	c   net.Conn
	e   *list.Element
	w   *wire.Session
	geo *geo.Geometry

	id      uint64
	retrSeq uint32

	sendTokens    uint64
	maxSendTokens uint64

	sendTokenIncr time.Duration
	sendTokenLast time.Time

	isInitialized bool // Set by listener.
	fromClient    bool
	fromMix       bool
	canSend       bool

	closeConnectionCh chan bool
}

func (c *incomingConn) IsPeerValid(creds *wire.PeerCredentials) bool {
	gateway := c.l.glue.Gateway()
	// this node is a provider
	if gateway != nil {
		// see if it is from a Mix
		_, canSend, isValid := c.l.glue.PKI().AuthenticateConnection(creds, false)
		if isValid {
			c.fromMix = true
			c.fromClient = false
			c.canSend = canSend
			return isValid
		}
		isClient := gateway.AuthenticateClient(creds)
		if !isClient && c.fromClient {
			// This used to be a client, but is no longer listed in
			// the user db.  Reject.
			c.canSend = false
			return false
		} else if isClient {
			// Ok this is a connection from a client.
			c.fromClient = true
			c.canSend = true // Clients can always send for now.

			// Update the rate limiter parameters.
			if c.l.glue.Config().Debug.DisableRateLimit {
				return true
			}

			// send token duration
			sendRatePerMinute := atomic.LoadUint64(&c.l.sendRatePerMinute)
			ratePerMin := float64(sendRatePerMinute)
			sendTokenDuration := uint64((1 / ratePerMin) * 60 * 1000)

			switch sendTokenDuration {
			case uint64(c.sendTokenIncr / time.Millisecond):
			// The send shift didn't change, don't update anything.
			case 0:
				c.log.Debugf("Rate limit disabled, no SendRatePerMinute.")
				c.sendTokenIncr = 0
				c.sendTokens = 0
				c.maxSendTokens = 0
			default:
				c.log.Debugf("Rate limit SendRatePerMinute updated: %v", c.sendTokenIncr)
			}
			// If there was no previous limit start at 1 send credit.
			if c.sendTokenIncr == 0 {
				c.sendTokens = 1
				c.sendTokenLast = time.Now()
			}
			c.sendTokenIncr = time.Duration(sendTokenDuration) * time.Millisecond

			// max send tokens
			c.maxSendTokens = atomic.LoadUint64(&c.l.sendBurst)
			switch c.maxSendTokens {
			case 0:
				c.log.Debugf("Rate limit disabled, no MaxSendTokens.")
				c.sendTokenIncr = 0
				c.sendTokens = 0
				c.maxSendTokens = 0
			default:
				c.log.Debugf("Rate limit MaxSendTokens updated: %v", c.maxSendTokens)
			}

			return true
		}

		// Connection is not from a client, so see if it's a mix.
	}

	// Well, the peer has to be a mix since we're not a provider, or the user
	// is unknown.
	var isValid bool
	c.fromClient = false
	_, c.canSend, isValid = c.l.glue.PKI().AuthenticateConnection(creds, false)
	if isValid {
		c.fromMix = true
	} else {
		blob, err := creds.PublicKey.MarshalBinary()
		if err != nil {
			panic(err)
		}
		c.log.Debugf("Authentication failed: '%x' (%x)", creds.AdditionalData, hash.Sum256(blob))
	}

	return isValid
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
	identityHash := hash.Sum256From(c.l.glue.IdentityPublicKey())
	cfg := &wire.SessionConfig{
		KEMScheme:         c.scheme,
		Geometry:          c.geo,
		Authenticator:     c,
		AdditionalData:    identityHash[:],
		AuthenticationKey: c.l.glue.LinkKey(),
		RandomReader:      rand.Reader,
	}
	var err error
	c.l.Lock()
	c.w, err = wire.NewSession(cfg, false)
	c.l.Unlock()
	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		return
	}
	defer c.w.Close()

	// Bind the session to the conn, handshake, authenticate.
	timeoutMs := time.Duration(c.l.glue.Config().Debug.HandshakeTimeout) * time.Millisecond
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
	for _, s := range c.l.glue.Listeners() {
		err := s.CloseOldConns(c)
		if err != nil {
			c.log.Errorf("Closing new connection because something is broken: " + err.Error())
			return
		}
	}

	// Start the reauthenticate ticker.
	reauthMs := time.Duration(c.l.glue.Config().Debug.ReauthInterval) * time.Millisecond
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

		instrument.Incoming(rawCmd)
		if c.fromClient {
			switch cmd := rawCmd.(type) {
			case *commands.SendRetrievePacket:
				c.log.Debugf("Received SendRetrievePacket from client.")
				if err := c.onSendRetrievePacket(cmd); err != nil {
					c.log.Debugf("Failed to handle RetreiveMessage: %v", err)
					return
				}
				continue
			case *commands.RetrieveMessage:
				c.log.Debugf("Received RetrieveMessage from peer.")
				if err := c.onRetrieveMessage(cmd); err != nil {
					c.log.Debugf("Failed to handle RetreiveMessage: %v", err)
					return
				}
				continue
			case *commands.GetConsensus:
				c.log.Infof("Received GetConsensus from peer.")
				if err := c.onGetConsensus(cmd); err != nil {
					c.log.Debugf("Failed to handle GetConsensus: %v", err)
					return
				}
				continue
			case *commands.GetConsensus2:
				c.log.Infof("Received GetConsensus2 from peer.")
				if err := c.onGetConsensus2(cmd); err != nil {
					c.log.Infof("Failed to handle GetConsensus2: %v", err)
					return
				}
				continue
			default:
				// Probably a common command, like SendPacket.
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
		c.log.Debugf("Received unexpected command: %T", cmd)
	}
	return false
}

func (c *incomingConn) onGetConsensus(cmd *commands.GetConsensus) error {
	c.log.Info("onGetConsensus")
	respCmd := &commands.Consensus{}
	rawDoc, err := c.l.glue.PKI().GetRawConsensus(cmd.Epoch)
	switch err {
	case nil:
		respCmd.ErrorCode = commands.ConsensusOk
		respCmd.Payload = rawDoc
	case cpki.ErrNoDocument:
		respCmd.ErrorCode = commands.ConsensusGone
	default: // Covers errNotCached
		respCmd.ErrorCode = commands.ConsensusNotFound
	}
	return c.w.SendCommand(respCmd)
}

func (c *incomingConn) onGetConsensus2(cmd *commands.GetConsensus2) error {
	c.log.Info("onGetConsensus2")
	respCmd := &commands.Consensus2{}

	c.log.Info("BEFORE calling GetRawConsensus")
	rawDoc, err := c.l.glue.PKI().GetRawConsensus(cmd.Epoch)
	c.log.Info("AFTER calling GetRawConsensus")

	switch err {
	case nil:
		c.log.Info("err is nil")
		respCmd.ErrorCode = commands.ConsensusOk
		respCmd.Payload = rawDoc
	case cpki.ErrNoDocument:
		c.log.Infof("err ConsensusGone : %s", err)
		respCmd.ErrorCode = commands.ConsensusGone
	default: // Covers errNotCached
		c.log.Infof("err ConsensusNotFound : %s", err)
		respCmd.ErrorCode = commands.ConsensusNotFound
	}

	chunkSize := cmd.Cmds.MaxMessageLenServerToClient
	c.log.Infof("chunk size %d", chunkSize)

	chunks, err := cpki.Chunk(rawDoc, chunkSize)
	if err != nil {
		return err
	}
	for i := 0; i < len(chunks); i++ {
		c.log.Infof("Sending chunk %d", i)
		chunk := chunks[i]
		chunkCmd := &commands.Consensus2{
			Cmds:       cmd.Cmds,
			ErrorCode:  0,
			ChunkNum:   uint32(i),
			ChunkTotal: uint32(len(chunks)),
			Payload:    chunk,
		}
		err := c.w.SendCommand(chunkCmd)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *incomingConn) onSendRetrievePacket(cmd *commands.SendRetrievePacket) error {
	pkt, err := packet.New(cmd.SphinxPacket, c.geo)
	if err != nil {
		return err
	}
	c.l.incomingCh <- pkt

	creds, err := c.w.PeerCredentials()
	if err != nil {
		return err
	}
	advance := true
	msg, surbID, _, err := c.l.glue.Gateway().Spool().Get(creds.AdditionalData, advance)
	if err != nil {
		return err
	}
	surbIDar := [constants.SURBIDLength]byte{}
	copy(surbIDar[:], surbID)
	respCmd := &commands.SendRetrievePacketReply{
		Geo:  c.geo,
		Cmds: commands.NewMixnetCommands(c.geo),

		SURBID:  surbIDar,
		Payload: msg,
	}
	return c.w.SendCommand(respCmd)
}

func (c *incomingConn) onRetrieveMessage(cmd *commands.RetrieveMessage) error {
	advance := false
	switch cmd.Sequence {
	case c.retrSeq:
		c.log.Debugf("RetrieveMessage: %d", cmd.Sequence)
	case c.retrSeq + 1:
		c.log.Debugf("RetrieveMessage: %d (Popping head)", cmd.Sequence)
		c.retrSeq++ // Advance the sequence number.
		advance = true
	default:
		return fmt.Errorf("provider: RetrieveMessage out of sequence: %d", cmd.Sequence)
	}

	// Get the message from the user's spool, advancing as appropriate.
	creds, err := c.w.PeerCredentials()
	if err != nil {
		return err
	}
	msg, surbID, remaining, err := c.l.glue.Gateway().Spool().Get(creds.AdditionalData, advance)
	if err != nil {
		return err
	}
	if remaining > math.MaxUint8 {
		// The count hint is an 8 bit value and is clamped.
		remaining = math.MaxUint8
	}
	hint := uint8(remaining)
	instrument.IngressQueue(hint)

	var respCmd commands.Command
	if surbID != nil {
		// This was a SURBReply.
		surbCmd := &commands.MessageACK{
			Geo:  c.geo,
			Cmds: commands.NewMixnetCommands(c.geo),

			QueueSizeHint: hint,
			Sequence:      cmd.Sequence,
			Payload:       msg,
		}
		copy(surbCmd.ID[:], surbID)
		respCmd = surbCmd

		if len(msg) != c.geo.PayloadTagLength+c.geo.ForwardPayloadLength {
			return fmt.Errorf("stored SURBReply payload is mis-sized: %v", len(msg))
		}
	} else if msg != nil {
		// This was a message.
		respCmd = &commands.Message{
			Geo:  c.geo,
			Cmds: commands.NewMixnetCommands(c.geo),

			QueueSizeHint: hint,
			Sequence:      cmd.Sequence,
			Payload:       msg,
		}
		if len(msg) != c.geo.UserForwardPayloadLength {
			return fmt.Errorf("stored user payload is mis-sized: %v", len(msg))
		}
	} else {
		// Queue must be empty.
		if hint != 0 {
			// This should NEVER happen, but it's probably not worth crashing
			// the server over if it does.
			c.log.Errorf("BUG: Get() failed to return a message, and the queue is not empty.")
		}
		respCmd = &commands.MessageEmpty{
			Cmds:     commands.NewMixnetCommands(c.geo),
			Sequence: cmd.Sequence,
		}
	}

	return c.w.SendCommand(respCmd)
}

func (c *incomingConn) onSendPacket(cmd *commands.SendPacket) error {
	pkt, err := packet.New(cmd.SphinxPacket, c.geo)
	if err != nil {
		return err
	}

	// Providers need to track packets received from other mixes vs
	// packets received from clients, avoid attempts by the final layer
	// to try to loop traffic back into the mix net, and sending packets
	// that bypass the mix net.
	pkt.MustForward = c.fromClient
	pkt.MustTerminate = c.l.glue.Config().Server.IsServiceNode && !c.fromClient

	// If the packet was from the client, and there is a SendShift for the
	// current epoch, enforce SendShift based rate limits.
	if c.fromClient && c.sendTokenIncr != 0 {
		// Update the token bucket for the time that we were idle.
		deltaT := time.Now().Sub(c.sendTokenLast)
		c.log.Debugf("Rate limit: DeltaT: %v Tokens: %v", deltaT, c.sendTokens)
		incrCount := uint64(deltaT / c.sendTokenIncr)
		if incrCount > 0 {
			c.sendTokenLast = c.sendTokenLast.Add(c.sendTokenIncr * time.Duration(incrCount))
			c.sendTokens += incrCount

			// Leaky bucket.
			if c.sendTokens > c.maxSendTokens {
				c.sendTokens = c.maxSendTokens
			}
		}

		if c.sendTokens == 0 {
			c.log.Debugf("Dropping packet: %v (Rate limited)", pkt.ID)
			instrument.PacketsDropped()
			pkt.Dispose()
			return nil
		}
		c.sendTokens--
		c.log.Debugf("Rate limit: Remaining tokens: %v", c.sendTokens)
	}

	c.log.Debugf("Handing off packet: %v", pkt.ID)

	// For purposes of fudging the scheduling delay based on queue dwell
	// time, we treat the moment the packet is inserted into the crypto
	// worker queue as the time the packet was received.
	pkt.RecvAt = time.Now()
	c.l.incomingCh <- pkt

	return nil
}

func newIncomingConn(l *listener, conn net.Conn, geo *geo.Geometry, scheme kem.Scheme, pkiSignScheme sign.Scheme) *incomingConn {
	c := &incomingConn{
		scheme:            scheme,
		pkiSignScheme:     pkiSignScheme,
		l:                 l,
		c:                 conn,
		id:                atomic.AddUint64(&incomingConnID, 1), // Diagnostic only, wrapping is fine.
		sendTokenLast:     time.Now(),
		maxSendTokens:     4, // Reasonable burst to avoid some unnecessary rate limiting.
		closeConnectionCh: make(chan bool),
		geo:               geo,
	}
	c.log = l.glue.LogBackend().GetLogger(fmt.Sprintf("incoming:%d", c.id))

	c.log.Debugf("New incoming connection: %v", conn.RemoteAddr())

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection list.

	return c
}
