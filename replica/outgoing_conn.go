// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

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
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/http/common"
)

var outgoingConnID uint64

type outgoingConn struct {
	scheme kem.Scheme
	geo    *geo.Geometry
	co     GenericConnector
	log    *logging.Logger

	dst *cpki.ReplicaDescriptor
	ch  chan commands.Command

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
		return false
	}
	keyblob, err := creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if !hmac.Equal(c.dst.LinkKey, keyblob) {
		c.log.Debug("IsPeerValid false, link key mismatch")
		return false
	}

	// Query the PKI to figure out if we can send or not, and to ensure that
	// the peer is listed in a PKI document that's valid.
	var isValid bool
	_, isValid = c.co.Server().pkiWorker.AuthenticateReplicaConnection(creds)

	if !isValid {
		c.log.Debug("failed to authenticate connect via latest PKI doc")
	}
	return isValid
}

func (c *outgoingConn) dispatchCommand(cmd commands.Command) {
	select {
	case c.ch <- cmd:
	default:
		// Drop-tail.  This would be better as a RingChannel from the channels
		// package (Drop-head), but it doesn't provide a way to tell if the
		// item was discared or not.
		//
		// The drops here should basically only happen if the link is down,
		// since the connection worker will handle dropping commands when the
		// link is congested.
		//
		// Note: Not logging here because this would get spammy, and we may be
		// under catastrophic load, in which case we can't afford to log.
	}
}

func (c *outgoingConn) worker() {
	var (
		// NOTE(david): we might need to adjust these to be aligned with our pki worker thread
		retryIncrement = epochtime.Period / 64
		maxRetryDelay  = epochtime.Period / 8
	)

	defer func() {
		c.log.Debugf("Halting connect worker.")
		c.co.OnClosedConn(c)
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
		KeepAlive: KeepAliveInterval,
		Timeout:   time.Duration(c.co.Server().cfg.ConnectTimeout) * time.Millisecond,
	}
	go func() {
		// Bolt a bunch of channels to the dial canceler, such that closing
		// either channel results in the dial context being canceled.
		select {
		case <-c.co.CloseAllCh():
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
		// dialing state since the Connector relies on outgoingConnection
		// objects to remove themselves from the connection table.
		if desc, isValid := c.co.Server().pkiWorker.AuthenticateReplicaConnection(&dialCheckCreds); isValid {
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
		for _, t := range cpki.ClientTransports {
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
			start := time.Now()

			// Handle the new connection.
			if c.onConnEstablished(conn, dialCtx.Done()) {
				// Canceled with a connection established.
				c.log.Debugf("Existing connection canceled.")
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
	identityHash := hash.Sum256From(c.co.Server().identityPublicKey)
	cfg := &wire.SessionConfig{
		KEMScheme:         c.scheme,
		Geometry:          c.geo,
		Authenticator:     c,
		AdditionalData:    identityHash[:],
		AuthenticationKey: c.co.Server().linkKey,
		RandomReader:      rand.Reader,
	}
	envelopeScheme := schemes.ByName(c.co.(*Connector).server.cfg.ReplicaNIKEScheme)
	isInitiator := true
	w, err := wire.NewStorageReplicaSession(cfg, envelopeScheme, isInitiator)
	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		return
	}
	defer w.Close()

	// Bind the session to the conn, handshake, authenticate.
	timeoutMs := time.Duration(c.co.Server().cfg.HandshakeTimeout) * time.Millisecond
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

	cmdCh := make(chan commands.Command)
	cmdCloseCh := make(chan error)
	defer close(cmdCh)
	go func() {
		defer close(cmdCloseCh)
		for {
			cmd, ok := <-cmdCh
			if !ok {
				return
			}
			if err := w.SendCommand(cmd); err != nil {
				c.log.Debugf("SendCommand failed: %v", err)
				return
			}
		}
	}()

	// Start the reauthenticate ticker.
	reauthMs := time.Duration(c.co.Server().cfg.ReauthInterval) * time.Millisecond
	reauth := time.NewTicker(reauthMs)
	defer reauth.Stop()

	for {
		var cmd commands.Command
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
		case cmd = <-c.ch:
		}

		if !c.canSend {
			// This is presumably a early connect, and we aren't allowed to
			// actually send commands to the peer yet.
			c.log.Debugf("Dropping replica command: %v (Not yet connected to outbound replica node.)", cmd)
			continue
		}

		// Use a go routine to actually send commands to the peer so that
		// cancelation can happen, even when mid SendCommand().
		select {
		case <-closeCh:
			// Halted while trying to send a command to the remote peer.
			wasHalted = true
			return
		case <-cmdCloseCh:
			// Something blew up when sending the command to the remote peer.
			return
		case cmdCh <- cmd:
			// Pass the command onto the worker that actually handles writing.
		}
	}
}

func newOutgoingConn(co GenericConnector, dst *cpki.ReplicaDescriptor, geo *geo.Geometry, scheme kem.Scheme) *outgoingConn {
	const maxQueueSize = 64 // TODO/perf: Tune this.

	c := &outgoingConn{
		scheme: scheme,
		geo:    geo,
		co:     co,
		dst:    dst,
		ch:     make(chan commands.Command, maxQueueSize),
		id:     atomic.AddUint64(&outgoingConnID, 1), // Diagnostic only, wrapping is fine.
	}
	c.log = co.Server().LogBackend().GetLogger(fmt.Sprintf("outgoing:%d", c.id))

	c.log.Debugf("New outgoing connection: %+v", dst)

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection map.

	return c
}
