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

package outgoing

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/monotime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/server/internal/constants"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"gopkg.in/op/go-logging.v1"
)

var outgoingConnID uint64

type outgoingConn struct {
	co  *connector
	log *logging.Logger

	dst *cpki.MixDescriptor
	ch  chan *packet.Packet

	id         uint64
	retryDelay time.Duration
	canSend    bool
}

var (
	outgoingConns = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: constants.Namespace,
			Name:      "outgoing_connections_total",
			Subsystem: constants.OutgoingConnSubsystem,
			Help:      "Number of outgoing connections",
		},
	)
	canceledOutgoingConns = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: constants.Namespace,
			Name:      "canceled_outgoing_connections_total",
			Subsystem: constants.OutgoingConnSubsystem,
			Help:      "Number of cancelled outgoing connections",
		},
	)
	packetsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: constants.Namespace,
			Name:      "dropped_packets_total",
			Subsystem: constants.OutgoingConnSubsystem,
			Help:      "Number of dropped packets",
		},
	)
)

// InitPrometheus registers prometheus metrics
func init() {
	prometheus.MustRegister(outgoingConns)
	prometheus.MustRegister(canceledOutgoingConns)
	prometheus.MustRegister(packetsDropped)
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
	var isValid bool
	_, c.canSend, isValid = c.co.glue.PKI().AuthenticateConnection(creds, true)

	return isValid
}

func (c *outgoingConn) dispatchPacket(pkt *packet.Packet) {
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
		pkt.Dispose()
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
		KeepAlive: constants.KeepAliveInterval,
		Timeout:   time.Duration(c.co.glue.Config().Debug.ConnectTimeout) * time.Millisecond,
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

	identityHash := c.dst.IdentityKey.Sum256()
	dialCheckCreds := wire.PeerCredentials{
		AdditionalData: identityHash[:],
		PublicKey:      c.dst.LinkKey,
	}

	// Establish the outgoing connection.
	for {
		// Check to see if the connection should be made in the first
		// place by seeing if the connection is in the PKI.  Without
		// something like this, stale connections can get stuck in the
		// dialing state since the connector relies on outgoingConnection
		// objects to remove themselves from the connection table.
		if desc, _, isValid := c.co.glue.PKI().AuthenticateConnection(&dialCheckCreds, true); isValid {
			// The list of addresses could have changed, authenticateConnection
			// will return the most "current" descriptor on success, so update
			// the cached pointer.
			if desc != nil {
				c.dst = desc
				dialCheckCreds.PublicKey = c.dst.LinkKey
			}
		} else {
			c.log.Debugf("Bailing out of Dial loop, no longer in PKI.")
			return
		}

		// Flatten the lists of addresses to Dial to.
		var dstAddrs []string
		for _, t := range cpki.InternalTransports {
			if v, ok := c.dst.Addresses[t]; ok {
				dstAddrs = append(dstAddrs, v...)
			}
		}
		if len(dstAddrs) == 0 {
			// Should *NEVER* happen because descriptors currently MUST have
			// at least once `tcp4` address to be considered valid.
			c.log.Warningf("Bailing out of Dial loop, no suitable addresses found.")
			return
		}

		for _, addrPort := range dstAddrs {
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
			outgoingConns.Inc()

			start := time.Now()

			// Handle the new connection.
			if c.onConnEstablished(conn, dialCtx.Done()) {
				// Canceled with a connection established.
				c.log.Debugf("Existing connection canceled.")
				canceledOutgoingConns.Inc()
				return
			}

			// That's odd, the connection died, reconnect.
			c.log.Debugf("Connection terminated, will reconnect.")
			if time.Since(start) < retryIncrement {
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
	identityHash := c.co.glue.IdentityPublicKey().Sum256()
	cfg := &wire.SessionConfig{
		Geometry:          sphinx.DefaultGeometry(),
		Authenticator:     c,
		AdditionalData:    identityHash[:],
		AuthenticationKey: c.co.glue.LinkKey(),
		RandomReader:      rand.Reader,
	}
	w, err := wire.NewSession(cfg, true)
	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		return
	}
	defer w.Close()

	// Bind the session to the conn, handshake, authenticate.
	timeoutMs := time.Duration(c.co.glue.Config().Debug.HandshakeTimeout) * time.Millisecond
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

	pktCh := make(chan *packet.Packet)
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
				SphinxPacket: pkt.Raw,
			}
			if err := w.SendCommand(&cmd); err != nil {
				c.log.Debugf("Dropping packet: %v (SendCommand failed: %v)", pkt.ID, err)
				packetsDropped.Inc()
				pkt.Dispose()
				return
			}
			c.log.Debugf("Sent packet: %v", pkt.ID)
			pkt.Dispose()
		}
	}()

	// Start the reauthenticate ticker.
	reauthMs := time.Duration(c.co.glue.Config().Debug.ReauthInterval) * time.Millisecond
	reauth := time.NewTicker(reauthMs)
	defer reauth.Stop()

	// Shuffle packets from the send queue out to the peer.
	for {
		var pkt *packet.Packet
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
			creds, err := w.PeerCredentials()
			if err != nil {
				c.log.Debugf("Session fail: %s", err)
				return
			}
			if !c.IsPeerValid(creds) {
				c.log.Debugf("Disconnecting, peer reauthenticate failed.")
				return
			}
			continue
		case pkt = <-c.ch:
			// Check the packet queue dwell time and drop it if it is excessive.
			now := monotime.Now()
			if now-pkt.DispatchAt > time.Duration(c.co.glue.Config().Debug.SendSlack)*time.Millisecond {
				c.log.Debugf("Dropping packet: %v (Deadline blown by %v)", pkt.ID, now-pkt.DispatchAt)
				packetsDropped.Inc()
				pkt.Dispose()
				continue
			}
		}

		if !c.canSend {
			// This is presumably a early connect, and we aren't allowed to
			// actually send packets to the peer yet.
			c.log.Debugf("Dropping packet: %v (Out of epoch)", pkt.ID)
			packetsDropped.Inc()
			pkt.Dispose()
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

	c := &outgoingConn{
		co:  co,
		dst: dst,
		ch:  make(chan *packet.Packet, maxQueueSize),
		id:  atomic.AddUint64(&outgoingConnID, 1), // Diagnostic only, wrapping is fine.
	}
	c.log = co.glue.LogBackend().GetLogger(fmt.Sprintf("outgoing:%d", c.id))

	c.log.Debugf("New outgoing connection: %+v", dst)

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection map.

	return c
}
