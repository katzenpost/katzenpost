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
	"context"
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
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/http/common"
	"github.com/katzenpost/katzenpost/server/internal/constants"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

var outgoingConnID uint64

type outgoingConn struct {
	scheme kem.Scheme
	geo    *geo.Geometry
	co     *connector
	log    *logging.Logger

	dst *cpki.MixDescriptor
	ch  chan *packet.Packet

	id         uint64
	retryDelay time.Duration
	canSend    bool
}

func (c *outgoingConn) IsPeerValid(creds *wire.PeerCredentials) bool {
	// At a minimum, the peer's credentials should match what we started out
	// with.  This is enforced even if mix authentication is disabled.

	idHash := hash.Sum256(c.dst.IdentityKey)
	if !hmac.Equal(idHash[:], creds.AdditionalData) {
		c.log.Debug("IsPeerValid false, identity hash mismatch")
		c.log.Errorf("IsPeerValid false, expect identity hash %x but got %x", idHash[:], creds.AdditionalData)
		return false
	}
	keyblob, err := creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if !hmac.Equal(c.dst.LinkKey, keyblob) {
		c.log.Debug("IsPeerValid false, link key mismatch")

		expectedLinkPubKey, err := c.scheme.UnmarshalBinaryPublicKey(c.dst.LinkKey)
		if err != nil {
			panic(err)
		}
		expected := pem.ToPublicPEMString(expectedLinkPubKey)
		got := pem.ToPublicPEMString(creds.PublicKey)
		c.log.Errorf("IsPeerValid false, link key mismatch, expected %s but got %s", expected, got)
		return false
	}

	// Query the PKI to figure out if we can send or not, and to ensure that
	// the peer is listed in a PKI document that's valid.
	var isValid bool
	_, c.canSend, isValid = c.co.glue.PKI().AuthenticateConnection(creds, true)

	if !isValid {
		c.log.Debug("failed to authenticate connect via latest PKI doc")
	}
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
	var (
		retryIncrement = epochtime.Period / 64
		maxRetryDelay  = epochtime.Period / 8
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

	identityHash := hash.Sum256(c.dst.IdentityKey)
	linkPubKey, err := c.scheme.UnmarshalBinaryPublicKey(c.dst.LinkKey)
	if err != nil {
		panic(err)
	}
	dialCheckCreds := wire.PeerCredentials{
		AdditionalData: identityHash[:],
		PublicKey:      linkPubKey,
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
				linkPubKey, err := c.scheme.UnmarshalBinaryPublicKey(c.dst.LinkKey)
				if err != nil {
					panic(err)
				}
				dialCheckCreds.PublicKey = linkPubKey
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

		for _, addr := range dstAddrs {
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
			u, err := url.Parse(addr)
			if err != nil {
				c.log.Warningf("Failed to parse addr: %v", err)
				continue
			}
			c.log.Debugf("Dialing: %v", u.Host)

			conn, err := common.DialURL(u, dialCtx, dialer.DialContext)
			select {
			case <-dialCtx.Done():
				// Canceled.
				if conn != nil {
					conn.Close()
				}
				return
			default:
				if err != nil {
					c.log.Warningf("Failed to connect to '%v': %v", u.Host, err)
					continue
				}
			}
			c.log.Debugf("%v connection established.", u.Scheme)
			instrument.Outgoing()
			start := time.Now()

			// Handle the new connection.
			if c.onConnEstablished(conn, dialCtx.Done()) {
				// Canceled with a connection established.
				c.log.Debugf("Existing connection canceled.")
				instrument.CancelledOutgoing()
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
	identityHash := hash.Sum256From(c.co.glue.IdentityPublicKey())
	cfg := &wire.SessionConfig{
		KEMScheme:         c.scheme,
		Geometry:          c.geo,
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
				Cmds:         w.GetCommands(),
			}
			if err := w.SendCommand(&cmd); err != nil {
				c.log.Debugf("Dropping packet: %v (SendCommand failed: %v)", pkt.ID, err)
				instrument.PacketsDropped()
				instrument.OutgoingPacketsDropped()
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
			now := time.Now()
			if now.Sub(pkt.DispatchAt) > time.Duration(c.co.glue.Config().Debug.SendSlack)*time.Millisecond {
				c.log.Debugf("Dropping packet: %v (Deadline blown by %v)", pkt.ID, now.Sub(pkt.DispatchAt))
				instrument.DeadlineBlownPacketsDropped()
				instrument.OutgoingPacketsDropped()
				instrument.PacketsDropped()
				pkt.Dispose()
				continue
			}
		}

		if !c.canSend {
			// This is presumably a early connect, and we aren't allowed to
			// actually send packets to the peer yet.
			c.log.Debugf("Dropping packet: %v (Not yet connected to outbound mix node.)", pkt.ID)
			instrument.OutgoingPacketsDropped()
			instrument.PacketsDropped()
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

func newOutgoingConn(co *connector, dst *cpki.MixDescriptor, geo *geo.Geometry, scheme kem.Scheme) *outgoingConn {
	const maxQueueSize = 64 // TODO/perf: Tune this.

	c := &outgoingConn{
		scheme: scheme,
		geo:    geo,
		co:     co,
		dst:    dst,
		ch:     make(chan *packet.Packet, maxQueueSize),
		id:     atomic.AddUint64(&outgoingConnID, 1), // Diagnostic only, wrapping is fine.
	}
	c.log = co.glue.LogBackend().GetLogger(fmt.Sprintf("outgoing:%d", c.id))

	c.log.Debugf("New outgoing connection: %+v", dst)

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection map.

	return c
}
