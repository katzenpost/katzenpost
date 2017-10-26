// outgoing_conn.go - Katzenpost server outgoing connection handler.
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
	"bytes"
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/monotime"
	cpki "github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/wire/commands"
	"github.com/op/go-logging"
)

const keepAliveInterval = 3 * time.Minute

var outgoingConnID uint64

type outgoingConn struct {
	s   *Server
	co  *connector
	dst *cpki.MixDescriptor
	ch  chan *packet
	log *logging.Logger

	id         uint64
	retryDelay time.Duration
	canSend    bool
}

func (c *outgoingConn) IsPeerValid(creds *wire.PeerCredentials) bool {
	// At a minimum, the peer's credentials should match what we started out
	// with.  This is enforced even if mix authentication is disabled.
	if !bytes.Equal(c.dst.IdentityKey.Bytes(), creds.AdditionalData) {
		return false
	}
	if !c.dst.LinkKey.Equal(creds.PublicKey) {
		return false
	}

	// Query the PKI to figure out if we can send or not, and to ensure that
	// the peer is listed in a PKI document that's valid.
	isValid := false
	_, c.canSend, isValid = c.s.pki.authenticateOutgoing(creds)

	return isValid
}

func (c *outgoingConn) dispatchPacket(pkt *packet) {
	select {
	case c.ch <- pkt:
	default:
		// Drop-tail.  This would be better as a RingChannel from the channels
		// package (Drop-head), but it doesn't provide a way to tell if the
		// item was discared or not.
		//
		// The drops here should basically only happen if the link is down,
		// since the connection worker will handle dropping packets when the
		// link is congested.
		//
		// Note: Not logging here because this would get spammy, and we may be
		// under catastrophic load, in which case we can't afford to log.
		pkt.dispose()
	}
}

func (c *outgoingConn) worker() {
	const (
		retryIncrement = 15 * time.Second
		maxRetryDelay  = 120 * time.Second
	)

	defer func() {
		c.log.Debugf("Halting connect worker.")
		c.co.onClosedConn(c)
		close(c.ch)
	}()

	// Sigh, I assume the correct thing to do is to use context for everything,
	// but the whole package feels like a shitty hack to make up for the fact
	// that Go lacks a real object model.
	//
	// So, use the context stuff via a bunch of shitty hacks to make up for the
	// fact that the server doesn't use context everywhere instead.
	dialCtx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()
	dialer := net.Dialer{
		KeepAlive: keepAliveInterval,
		Timeout:   time.Duration(c.s.cfg.Debug.ConnectTimeout) * time.Millisecond,
	}
	go func() {
		// Bolt a bunch of channels to the dial canceler, such that closing
		// either channel results in the dial context being canceled.
		select {
		case <-c.co.closeAllCh:
			cancelFn()
		case <-dialCtx.Done():
		}
	}()

	dialCheckCreds := wire.PeerCredentials{
		AdditionalData: c.dst.IdentityKey.Bytes(),
		PublicKey:      c.dst.LinkKey,
	}

	// Establish the outgoing connection.
	for {
		// Check to see if the connection should be made in the first
		// place by seeing if the connection is in the PKI.  Without
		// something like this, stale connections can get stuck in the
		// dialing state since the connector relies on outgoingConnection
		// objects to remove themselves from the connection table.
		if desc, _, isValid := c.s.pki.authenticateOutgoing(&dialCheckCreds); isValid {
			// The list of addresses could have changed, authenticateOutgoing
			// will return the most "current" descriptor in most cases, so
			// update the cached pointer.
			if desc != nil {
				c.dst = desc
				dialCheckCreds.PublicKey = c.dst.LinkKey
			}
		} else {
			c.log.Debugf("Bailing out of Dial loop, no longer in PKI.")
			return
		}

		for _, addrPort := range c.dst.Addresses {
			select {
			case <-time.After(c.retryDelay):
				// Back off incrementally on reconnects.
				//
				// This maybe should be tracked per address, but whatever.  I
				// remember when IPng was supposed to take over the world in
				// the 90s, and it still hasn't happened yet.
				c.retryDelay += retryIncrement
				if c.retryDelay > maxRetryDelay {
					c.retryDelay = maxRetryDelay
				}
			case <-dialCtx.Done():
				// Canceled mid-retry delay.
				c.log.Debugf("(Re)connection attempts canceled.")
				return
			}

			// Dial.
			c.log.Debugf("Dialing: %v", addrPort)
			conn, err := dialer.DialContext(dialCtx, "tcp", addrPort)
			select {
			case <-dialCtx.Done():
				// Canceled.
				if conn != nil {
					conn.Close()
				}
				return
			default:
				if err != nil {
					c.log.Warningf("Failed to connect to '%v': %v", addrPort, err)
					continue
				}
			}
			c.log.Debugf("TCP connection established.")
			start := time.Now()

			// Handle the new connection.
			if c.onConnEstablished(conn, dialCtx.Done()) {
				// Canceled with a connection established.
				c.log.Debugf("Existing connection canceled.")
				return
			}

			// That's odd, the connection died, reconnect.
			c.log.Debugf("Connection terminated, will reconnect.")
			if time.Now().Sub(start) < retryIncrement {
				// If the connection was not alive for a sensible amount of
				// time, re-impose a reconnect delay.
				c.retryDelay = retryIncrement
			}
			break
		}
	}
}

func (c *outgoingConn) onConnEstablished(conn net.Conn, closeCh <-chan struct{}) (wasHalted bool) {
	defer func() {
		c.log.Debugf("TCP connection closed. (wasHalted: %v)", wasHalted)
		conn.Close()
	}()

	// Allocate the session struct.
	cfg := &wire.SessionConfig{
		Authenticator:     c,
		AdditionalData:    c.s.identityKey.PublicKey().Bytes(),
		AuthenticationKey: c.s.linkKey,
		RandomReader:      rand.Reader,
	}
	w, err := wire.NewSession(cfg, true)
	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		return
	}
	defer w.Close()

	// Bind the session to the conn, handshake, authenticate.
	timeoutMs := time.Duration(c.s.cfg.Debug.HandshakeTimeout) * time.Millisecond
	conn.SetDeadline(time.Now().Add(timeoutMs))
	if err = w.Initialize(conn); err != nil {
		c.log.Errorf("Handshake failed: %v", err)
		return
	}
	c.log.Debugf("Handshake completed.")
	conn.SetDeadline(time.Time{})
	c.retryDelay = 0 // Reset the retry delay on successful handshakes.

	// Since outgoing connections have no reverse traffic, read from the
	// reverse path to detect that the connection has been closed.
	//
	// Incoming connections do not need similar treatment by virtue of
	// the fact that they are constantly reading.
	peerClosedCh := make(chan interface{})
	go func() {
		var oneByte [1]byte
		if n, err := conn.Read(oneByte[:]); n != 0 || err == nil {
			// This should *NEVER* happen past the handshake,
			// and is an invariant violation that will force close
			// the connection.
			c.log.Warningf("Peer sent reverse traffic.")
		}
		close(peerClosedCh)
	}()

	pktCh := make(chan *packet)
	pktCloseCh := make(chan error)
	defer close(pktCh)
	go func() {
		defer close(pktCloseCh)
		for {
			pkt, ok := <-pktCh
			if !ok {
				return
			}
			cmd := commands.SendPacket{
				SphinxPacket: pkt.raw,
			}
			if err := w.SendCommand(&cmd); err != nil {
				c.log.Debugf("Dropping packet: %v (SendCommand failed: %v)", pkt.id, err)
				pkt.dispose()
				return
			}
			c.log.Debugf("Sent packet: %v", pkt.id)
			pkt.dispose()
		}
	}()

	// Start the reauthenticate ticker.
	reauthMs := time.Duration(c.s.cfg.Debug.ReauthInterval) * time.Millisecond
	reauth := time.NewTicker(reauthMs)
	defer reauth.Stop()

	// Shuffle packets from the send queue out to the peer.
	for {
		var pkt *packet
		select {
		case <-peerClosedCh:
			c.log.Debugf("Connection closed by peer.")
			return
		case <-closeCh:
			wasHalted = true
			return
		case <-reauth.C:
			// Each outgoing connection has a periodic 1/15 Hz timer to wake up
			// and re-authenticate to handle the PKI document(s) changing.
			if !c.IsPeerValid(w.PeerCredentials()) {
				c.log.Debugf("Disconnecting, peer reauthenticate failed.")
				return
			}
			continue
		case pkt = <-c.ch:
			// Check the packet queue dwell time and drop it if it is excessive.
			now := monotime.Now()
			if now-pkt.dispatchAt > time.Duration(c.s.cfg.Debug.SendSlack)*time.Millisecond {
				c.log.Debugf("Dropping packet: %v (Deadline blown by %v)", pkt.id, now-pkt.dispatchAt)
				pkt.dispose()
				continue
			}
		}

		if !c.canSend {
			// This is presumably a early connect, and we aren't allowed to
			// actually send packets to the peer yet.
			c.log.Debugf("Dropping packet: %v (Out of epoch)", pkt.id)
			pkt.dispose()
			continue
		}

		// Use a go routine to actually send packets to the peer so that
		// cancelation can happen, even when mid SendCommand().
		select {
		case <-closeCh:
			// Halted while trying to send a packet to the remote peer.
			wasHalted = true
			return
		case <-pktCloseCh:
			// Something blew up when sending the packet to the remote peer.
			return
		case pktCh <- pkt:
			// Pass the packet onto the worker that actually handles writing.
		}
	}
}

func newOutgoingConn(co *connector, dst *cpki.MixDescriptor) *outgoingConn {
	const maxQueueSize = 64 // TODO/perf: Tune this.

	c := new(outgoingConn)
	c.s = co.s
	c.co = co
	c.dst = dst
	c.ch = make(chan *packet, maxQueueSize)
	c.id = atomic.AddUint64(&outgoingConnID, 1) // Diagnostic only, wrapping is fine.
	c.log = co.s.logBackend.GetLogger(fmt.Sprintf("outgoing:%d", c.id))

	c.log.Debugf("New outgoing connection: %+v", dst)

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection map.

	return c
}
