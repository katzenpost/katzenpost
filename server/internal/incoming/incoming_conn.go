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
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"

	kpcommon "github.com/katzenpost/katzenpost/common"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/wire/handshakeinstrument"
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

	isInitialized uint32 // Atomic flag, set by listener after handshake.
	fromClient    bool
	fromMix       bool
	canSend       bool

	// notifyCh is the wake signal for the sender goroutine. The
	// listener writes to it (non-blocking, coalescing) when the
	// gateway has just enqueued fresh spool work for this client. The
	// channel is buffered to depth one because the wake is
	// level-triggered: the sender always re-checks the spool after
	// servicing, so we only need to remember "at least one wake
	// pending."
	notifyCh chan struct{}

	// ackCh carries the Sequence value of an arriving
	// MessageDelivered from the client. The inbound dispatch writes
	// the value here; the sender goroutine reads it to advance the
	// spool. Buffered to depth one so a stray ack arriving between
	// sends never blocks the inbound worker.
	ackCh chan uint32

	closeConnectionCh chan bool
}

// notify wakes the sender goroutine so it drains the spool. Safe to
// call concurrently; coalesces redundant wakes via a depth-one buffer.
func (c *incomingConn) notify() {
	select {
	case c.notifyCh <- struct{}{}:
	default:
	}
}

func (c *incomingConn) IsPeerValid(creds *wire.PeerCredentials) bool {
	// Helper function to get peer name - returns name and whether peer was found in PKI
	getPeerName := func() (string, bool) {
		if doc, err := c.l.glue.PKI().CurrentDocument(); err == nil && doc != nil {
			var adHash [32]byte
			copy(adHash[:], creds.AdditionalData)
			if node, err := doc.GetNodeByKeyHash(&adHash); err == nil {
				return node.Name, true
			}
		}
		return "", false
	}

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
			peerName, found := getPeerName()
			if found {
				c.log.Warningf("server/incoming: IsPeerValid(): Client '%s' no longer in user db", peerName)
			} else {
				c.log.Warningf("server/incoming: IsPeerValid(): Client no longer in user db (identity_hash=%x not in current PKI)", creds.AdditionalData)
			}
			c.log.Debugf("server/incoming: IsPeerValid(): Remote Peer Credentials: name=%s, identity_hash=%x, link_key=%s",
				peerName, creds.AdditionalData, kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(creds.PublicKey)))
			handshakeinstrument.IncomingPeerValidationFailure("client_dropped_from_userdb")
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

			// Pull the latest token-bucket parameters that the PKI
			// worker derived from the consensus document's LambdaP
			// and LambdaL. Both atomics are zero until the first
			// consensus-document update, at which point the limiter
			// activates; both zero again disables it.
			incrNs := atomic.LoadUint64(&c.l.sendTokenIncrNs)
			maxTokens := atomic.LoadUint64(&c.l.maxSendTokens)
			newIncr := time.Duration(incrNs)

			switch {
			case newIncr == c.sendTokenIncr && maxTokens == c.maxSendTokens:
				// Unchanged. Preserve the running bucket state.
			case incrNs == 0:
				c.log.Debugf("Rate limit disabled, no client emission rate published.")
				c.sendTokenIncr = 0
				c.sendTokens = 0
				c.maxSendTokens = 0
			default:
				c.log.Debugf("Rate limit updated: %d ns per token, cap %d", incrNs, maxTokens)
				if c.sendTokenIncr == 0 {
					// Fresh activation: prime the bucket with one token.
					c.sendTokens = 1
					c.sendTokenLast = time.Now()
				}
				c.sendTokenIncr = newIncr
				c.maxSendTokens = maxTokens
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
		peerName, found := getPeerName()
		blob, err := creds.PublicKey.MarshalBinary()
		if err != nil {
			panic(err)
		}
		if found {
			c.log.Warningf("server/incoming: IsPeerValid(): Authentication failed for peer '%s' (link_key_hash=%x)", peerName, hash.Sum256(blob))
		} else {
			c.log.Warningf("server/incoming: IsPeerValid(): Authentication failed for unknown peer (identity_hash=%x not in current PKI, link_key_hash=%x)", creds.AdditionalData, hash.Sum256(blob))
		}
		c.log.Debugf("server/incoming: IsPeerValid(): Remote Peer Credentials: name=%s, identity_hash=%x, link_key=%s",
			peerName, creds.AdditionalData, kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(creds.PublicKey)))
		handshakeinstrument.IncomingPeerValidationFailure("unknown_mix")
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
	// Note: wire.NewSession() only creates the session object, it doesn't
	// access shared state, so no lock is needed here.
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
	c.w, err = wire.NewSession(cfg, false)
	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		return
	}
	defer c.w.Close()

	// Bind the session to the conn, handshake, authenticate.
	timeoutMs := time.Duration(c.l.glue.Config().Debug.HandshakeTimeout) * time.Millisecond
	c.c.SetDeadline(time.Now().Add(timeoutMs))
	handshakeStart := time.Now()
	if err = c.w.Initialize(c.c); err != nil {
		handshakeElapsed := time.Since(handshakeStart)
		state := "other"
		if he, ok := wire.GetHandshakeError(err); ok {
			state = string(he.State)
		} else if wire.IsNoHandshakeBytesError(err) {
			state = "premature_close"
		}
		handshakeinstrument.HandshakeFailure("incoming", state)
		handshakeinstrument.HandshakeDuration("incoming", "failure", handshakeElapsed)

		if wire.IsNoHandshakeBytesError(err) {
			c.log.Debugf(
				"TCP connection closed before Noise handshake bytes local=%v remote=%v after=%v timeout=%v: %v",
				c.c.LocalAddr(),
				c.c.RemoteAddr(),
				handshakeElapsed,
				timeoutMs,
				err,
			)
			return
		}

		c.log.Errorf(
			"Handshake failed local=%v remote=%v after=%v timeout=%v: %v",
			c.c.LocalAddr(),
			c.c.RemoteAddr(),
			handshakeElapsed,
			timeoutMs,
			err,
		)
		// Log detailed debug info (contains IPs, keys) at debug level only
		c.log.Debugf("Handshake failure details:\n%s", wire.GetDebugError(err))
		return
	}
	handshakeElapsed := time.Since(handshakeStart)
	handshakeinstrument.HandshakeDuration("incoming", "success", handshakeElapsed)
	c.log.Debugf(
		"Handshake completed local=%v remote=%v in %v",
		c.c.LocalAddr(),
		c.c.RemoteAddr(),
		handshakeElapsed,
	)
	c.c.SetDeadline(time.Time{})
	c.l.onInitializedConn(c)

	// Spawn the push-delivery sender for client connections. The
	// sender pushes spool entries as MessageACK as soon as
	// the listener pings it from the gateway worker, and sends NoOp
	// heartbeats during otherwise quiet stretches. Mix-to-mix
	// connections have no spool and skip this.
	if c.fromClient && c.l.glue.Gateway() != nil {
		go c.senderWorker()
	}

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
			instrument.PacketsDropped()
			instrument.PacketsDroppedByReason("incoming_out_of_epoch")
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
				// Push-delivery clients never send RetrieveMessage.
				// A stray one indicates an out-of-date peer; drop the
				// connection rather than silently going along.
				c.log.Debugf("Received unexpected RetrieveMessage from peer in push-delivery mode; closing.")
				return
			case *commands.MessageDelivered:
				// Acknowledgement of a MessageACK we pushed.
				// Hand the Sequence to the sender goroutine so it can
				// advance the spool. Non-blocking: a stale ack arriving
				// between sends would overwrite the pending value in
				// the depth-one buffer, which is fine because the
				// sender always validates the Sequence it consumes.
				select {
				case c.ackCh <- cmd.Sequence:
				default:
					select {
					case <-c.ackCh:
					default:
					}
					select {
					case c.ackCh <- cmd.Sequence:
					default:
					}
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

	c.log.Info("BEFORE calling GetRawConsensus")
	rawDoc, err := c.l.glue.PKI().GetRawConsensus(cmd.Epoch)
	c.log.Info("AFTER calling GetRawConsensus")

	var errorCode uint8
	switch err {
	case nil:
		c.log.Info("err is nil")
		errorCode = commands.ConsensusOk
	case cpki.ErrNoDocument:
		c.log.Infof("err ConsensusGone : %s", err)
		errorCode = commands.ConsensusGone
	default: // Covers errNotCached
		c.log.Infof("err ConsensusNotFound : %s", err)
		errorCode = commands.ConsensusNotFound
	}

	// For error responses, send a single empty chunk with the error code
	// rather than chunking a nil document.
	if errorCode != commands.ConsensusOk {
		respCmd := &commands.Consensus2{
			Cmds:       cmd.Cmds,
			ErrorCode:  errorCode,
			ChunkNum:   0,
			ChunkTotal: 1,
			Payload:    []byte{},
		}
		return c.w.SendCommand(respCmd)
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
			ErrorCode:  commands.ConsensusOk,
			ChunkNum:   uint32(i),
			ChunkTotal: uint32(len(chunks)),
			Payload:    chunk,
		}
		if err := c.w.SendCommand(chunkCmd); err != nil {
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

// senderWorker pushes MessageACK commands to a connected client as
// soon as the spool has work for them, and emits NoOp
// heartbeats during otherwise quiet stretches so the client's
// post-handshake read deadline stays warm. Spawned once per
// authenticated client connection by worker(); exits on connection
// teardown.
func (c *incomingConn) senderWorker() {
	const heartbeatInterval = 10 * time.Second
	const ackTimeout = 60 * time.Second

	defer c.log.Debugf("senderWorker exiting")

	heartbeat := time.NewTimer(heartbeatInterval)
	defer heartbeat.Stop()

	// Initial wake so a backlog accumulated while the client was
	// disconnected drains immediately on reconnect.
	c.notify()

	var seq uint32
	for {
		select {
		case <-c.l.closeAllCh:
			return
		case <-c.closeConnectionCh:
			return
		case <-heartbeat.C:
			cmd := &commands.NoOp{Cmds: commands.NewMixnetCommands(c.geo)}
			if err := c.w.SendCommand(cmd); err != nil {
				c.log.Debugf("senderWorker: NoOp send failed: %v", err)
				return
			}
			heartbeat.Reset(heartbeatInterval)
			continue
		case <-c.notifyCh:
		}

		creds, err := c.w.PeerCredentials()
		if err != nil {
			c.log.Debugf("senderWorker: PeerCredentials failed: %v", err)
			return
		}

		for {
			select {
			case <-c.l.closeAllCh:
				return
			case <-c.closeConnectionCh:
				return
			default:
			}

			msg, surbID, remaining, err := c.l.glue.Gateway().Spool().Get(creds.AdditionalData, false)
			if err != nil {
				c.log.Debugf("senderWorker: Spool.Get failed: %v", err)
				return
			}
			if msg == nil {
				break
			}
			if remaining > math.MaxUint8 {
				remaining = math.MaxUint8
			}
			hint := uint8(remaining)
			instrument.IngressQueue(hint)

			seq++
			mySeq := seq

			if surbID == nil {
				c.log.Errorf("senderWorker: spool entry has no SURB ID; cannot deliver as MessageACK")
				return
			}
			if len(msg) != c.geo.PayloadTagLength+c.geo.ForwardPayloadLength {
				c.log.Errorf("senderWorker: stored SURBReply payload is mis-sized: %v", len(msg))
				return
			}
			cmd := &commands.MessageACK{
				Geo:           c.geo,
				Cmds:          commands.NewMixnetCommands(c.geo),
				QueueSizeHint: hint,
				Sequence:      mySeq,
				Payload:       msg,
			}
			copy(cmd.ID[:], surbID)

			// Drain any stale ack that arrived before we sent this one
			// so it is not mistaken for the response we are about to
			// wait on.
			select {
			case <-c.ackCh:
			default:
			}

			if err := c.w.SendCommand(cmd); err != nil {
				c.log.Debugf("senderWorker: SendCommand failed: %v", err)
				return
			}

			ackTimer := time.NewTimer(ackTimeout)
			waitingForAck := true
			for waitingForAck {
				select {
				case <-c.l.closeAllCh:
					ackTimer.Stop()
					return
				case <-c.closeConnectionCh:
					ackTimer.Stop()
					return
				case <-ackTimer.C:
					c.log.Debugf("senderWorker: ack timeout waiting for seq %d", mySeq)
					return
				case ackSeq := <-c.ackCh:
					if ackSeq == mySeq {
						waitingForAck = false
					} else {
						c.log.Debugf("senderWorker: ignoring stale ack seq=%d (expected %d)", ackSeq, mySeq)
					}
				}
			}
			ackTimer.Stop()

			// Advance the spool past the entry the client just acked.
			if _, _, _, err := c.l.glue.Gateway().Spool().Get(creds.AdditionalData, true); err != nil {
				c.log.Debugf("senderWorker: Spool advance failed: %v", err)
				return
			}

			// We just sent traffic so push the heartbeat out.
			if !heartbeat.Stop() {
				select {
				case <-heartbeat.C:
				default:
				}
			}
			heartbeat.Reset(heartbeatInterval)
		}
	}
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

	// If the packet was from the client and the gateway has activated
	// its derived token-bucket limit (sendTokenIncr != 0 means a
	// positive LambdaP+LambdaL was published), enforce it.
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
			instrument.PacketsDroppedByReason("gateway_rate_limited")
			instrument.RateLimitDropped()
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
		notifyCh:          make(chan struct{}, 1),
		ackCh:             make(chan uint32, 1),
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
