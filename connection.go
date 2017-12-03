// connection.go - Client to provider connection.
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

package minclient

import (
	"bytes"
	"context"
	"net"
	"time"

	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/worker"
	"github.com/op/go-logging"
)

type connection struct {
	worker.Worker

	c   *Client
	log *logging.Logger

	pkiEpoch   uint64
	descriptor *cpki.MixDescriptor
	pkiFetchCh chan interface{}
}

func (c *connection) Halt() {
	c.Worker.Halt()

	// XXX: Cleanup.
}

func (c *connection) onPKIFetch() {
	select {
	case c.pkiFetchCh <- true:
	default:
		// Probably a connection is in progress, the right thing will happen
		// regardless of if the signal gets dropped, though it might require
		// the fallback timer to fire.
	}
}

func (c *connection) getDescriptor() {
	ok := false
	defer func() {
		if !ok {
			c.pkiEpoch = 0
			c.descriptor = nil
		}
	}()

	doc := c.c.pki.currentDocument()
	if doc == nil {
		c.log.Debugf("No PKI document for current epoch.")
		return
	}
	desc, err := doc.GetProvider(c.c.cfg.Provider)
	if err != nil {
		c.log.Debugf("Failed to find descriptor for Provider: %v", err)
		return
	}
	if desc != c.descriptor {
		c.log.Debugf("Descriptor for epoch %v: %+v", doc.Epoch, desc)
	}

	c.descriptor = desc
	c.pkiEpoch = doc.Epoch
	ok = true
}

func (c *connection) connectWorker() {
	defer c.log.Debugf("Terminating connect worker.")
	const pkiFallbackInterval = 3 * time.Minute

	dialCtx, cancelFn := context.WithCancel(context.Background())
	go func() {
		select {
		case <-c.HaltCh():
			cancelFn()
		case <-dialCtx.Done():
		}
	}()

	timer := time.NewTimer(pkiFallbackInterval)
	defer timer.Stop()
	for {
		timerFired := false

		// Wait for a signal from the PKI (or a fallback timer to pass)
		// before querying the PKI for a document iff we do not have the
		// Provider's current descriptor.
		if now, _, _ := epochtime.FromUnix(c.c.pki.skewedUnixTime()); now != c.pkiEpoch {
			select {
			case <-c.HaltCh():
				return
			case <-c.pkiFetchCh:
				c.log.Debugf("PKI fetch successful.")
			case <-timer.C:
				c.log.Debugf("PKI fetch fallback timer.")
				timerFired = true
			}
		}
		if !timerFired && !timer.Stop() {
			<-timer.C
		}

		// Query the PKI for the current descriptor.
		c.getDescriptor()
		if c.descriptor != nil {
			// Attempt to connect.
			c.doConnect(dialCtx)
		}
		select {
		case <-c.HaltCh():
			return
		default:
		}
		timer.Reset(pkiFallbackInterval)
	}

	// NOTREACHED
}

func (c *connection) doConnect(dialCtx context.Context) {
	const (
		keepAliveInterval = 3 * time.Minute
		connectTimeout    = 1 * time.Minute
		retryIncrement    = 15 * time.Second
		maxRetryDelay     = 2 * time.Minute
	)

	dialer := net.Dialer{
		KeepAlive: keepAliveInterval,
		Timeout:   connectTimeout,
	}

	retryDelay := 0 * time.Second
	for {
		c.getDescriptor()
		if c.descriptor == nil {
			c.log.Debugf("Aborting connect loop, descriptor no longer present.")
			return
		}

		for _, addrPort := range c.descriptor.Addresses {
			select {
			case <-time.After(retryDelay):
				// Back off the reconnect delay.
				retryDelay += retryIncrement
				if retryDelay > maxRetryDelay {
					retryDelay = maxRetryDelay
				}
			case <-c.HaltCh():
				c.log.Debugf("(Re)connection attempts canceled.")
				return
			}

			c.log.Debugf("Dialing: %v", addrPort)
			conn, err := dialer.DialContext(dialCtx, "tcp", addrPort)
			select {
			case <-c.HaltCh():
				if conn != nil {
					conn.Close()
				}
				return
			default:
				if err != nil {
					c.log.Warningf("Failed to connect to %v: %v", addrPort, err)
					continue
				}
				retryDelay = 0
			}
			c.log.Debugf("TCP connection established.")
			start := time.Now()

			// Do something with the connection.
			c.onConnection(conn)

			c.log.Debugf("Connection terminated, will reconnect.")
			if time.Since(start) < retryIncrement {
				// Don't reconnect in a tight loop if the handshake fails.
				retryDelay = retryIncrement
			}

			// Re-iterate through the address/ports on a sucessful connect.
			break
		}
	}
}

func (c *connection) onConnection(conn net.Conn) {
	const handshakeTimeout = 1 * time.Minute

	defer func() {
		c.log.Debugf("TCP connection closed.")
		conn.Close()
	}()

	// Allocate the session struct.
	cfg := &wire.SessionConfig{
		Authenticator:     c,
		AdditionalData:    []byte(c.c.cfg.User),
		AuthenticationKey: c.c.cfg.IdentityKey,
		RandomReader:      rand.Reader,
	}
	w, err := wire.NewSession(cfg, true)
	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		return
	}
	defer w.Close()

	// Bind the session to the conn, handshake, authenticate.
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err = w.Initialize(conn); err != nil {
		c.log.Errorf("Handshake failed: %v", err)
		return
	}
	c.log.Debugf("Handshake completed.")
	conn.SetDeadline(time.Time{})
	c.c.pki.setClockSkew(int64(w.ClockSkew().Seconds()))

	// XXX: Do something
	<-c.HaltCh()
}

func (c *connection) IsPeerValid(creds *wire.PeerCredentials) bool {
	// Refresh the peer's descriptor from the PKI fetcher.
	c.getDescriptor()
	if c.descriptor == nil {
		return false
	}

	if !bytes.Equal(c.descriptor.IdentityKey.Bytes(), creds.AdditionalData) {
		return false
	}
	if !c.descriptor.LinkKey.Equal(creds.PublicKey) {
		return false
	}
	return true
}

func newConnection(c *Client) *connection {
	k := new(connection)
	k.c = c
	k.log = c.cfg.LogBackend.GetLogger("minclient/conn:" + c.displayName)
	k.pkiFetchCh = make(chan interface{}, 1)

	k.Go(k.connectWorker)
	return k
}
