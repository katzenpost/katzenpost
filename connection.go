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
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/wire/commands"
	"github.com/katzenpost/core/worker"
	"gopkg.in/op/go-logging.v1"
)

const (
	keepAliveInterval = 3 * time.Minute
	connectTimeout    = 1 * time.Minute
)

var (
	// ErrNotConnected is the error returned when an operation fails due to the
	// client not currently being connected to the Provider.
	ErrNotConnected = errors.New("minclient/conn: not connected to the Provider")

	defaultDialer = net.Dialer{
		KeepAlive: keepAliveInterval,
		Timeout:   connectTimeout,
	}
)

type connection struct {
	sync.Mutex
	worker.Worker

	c   *Client
	log *logging.Logger

	pkiEpoch   uint64
	descriptor *cpki.MixDescriptor

	pkiFetchCh     chan interface{}
	fetchCh        chan interface{}
	sendCh         chan *connSendCtx
	getConsensusCh chan *getConsensusCtx

	retryDelay  time.Duration
	isConnected bool
}

type getConsensusCtx struct {
	replyCh chan interface{}
	epoch   uint64
	doneFn  func(error)
}

type connSendCtx struct {
	pkt    []byte
	doneFn func(error)
}

// ForceFetch attempts to force an otherwise idle client to attempt to fetch
// the contents of the user's spool.  This call has no effect if a connection
// is not established or if the connection is already in the middle of a
// fetch cycle, and should be considered a best effort operation.
func (c *Client) ForceFetch() {
	select {
	case c.conn.fetchCh <- true:
	default:
	}
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

	doc := c.c.CurrentDocument()
	if doc == nil {
		c.log.Debugf("No PKI document for current epoch.")
		return
	}
	desc, err := doc.GetProvider(c.c.cfg.Provider)
	if err != nil {
		c.log.Debugf("Failed to find descriptor for Provider: %v", err)
		return
	}
	if c.c.cfg.ProviderKeyPin != nil && !c.c.cfg.ProviderKeyPin.Equal(desc.IdentityKey) {
		c.log.Errorf("Provider identity key does not match pinned key: %v", desc.IdentityKey)
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
		retryIncrement = 15 * time.Second
		maxRetryDelay  = 2 * time.Minute
	)

	dialFn := c.c.cfg.DialContextFn
	if dialFn == nil {
		dialFn = defaultDialer.DialContext
	}

	for {
		c.getDescriptor()
		if c.descriptor == nil {
			c.log.Debugf("Aborting connect loop, descriptor no longer present.")
			return
		}

		// Build the list of candidate addresses, in decreasing order of
		// preference, by transport.
		var dstAddrs []string
		transports := c.c.cfg.PreferedTransports
		if transports == nil {
			transports = cpki.ClientTransports
		}
		for _, t := range transports {
			if v, ok := c.descriptor.Addresses[t]; ok {
				dstAddrs = append(dstAddrs, v...)
			}
		}
		if len(dstAddrs) == 0 {
			c.log.Warningf("Aborting connect loop, no suitable addresses found.")
			c.pkiEpoch = 0 // Give up till the next PKI fetch.
			return
		}

		for _, addrPort := range dstAddrs {
			select {
			case <-time.After(c.retryDelay):
				// Back off the reconnect delay.
				c.retryDelay += retryIncrement
				if c.retryDelay > maxRetryDelay {
					c.retryDelay = maxRetryDelay
				}
			case <-c.HaltCh():
				c.log.Debugf("(Re)connection attempts canceled.")
				return
			}

			c.log.Debugf("Dialing: %v", addrPort)
			conn, err := dialFn(dialCtx, "tcp", addrPort)
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
			}
			c.log.Debugf("TCP connection established.")

			// Do something with the connection.
			c.onTCPConn(conn)

			// Re-iterate through the address/ports on a sucessful connect.
			c.log.Debugf("Connection terminated, will reconnect.")
			break
		}
	}
}

func (c *connection) onTCPConn(conn net.Conn) {
	const handshakeTimeout = 1 * time.Minute
	var err error

	defer func() {
		c.log.Debugf("TCP connection closed.")
		conn.Close()
	}()

	// Allocate the session struct.
	cfg := &wire.SessionConfig{
		Authenticator:     c,
		AdditionalData:    []byte(c.c.cfg.User),
		AuthenticationKey: c.c.cfg.LinkKey,
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

	c.onWireConn(w)
}

func (c *connection) onWireConn(w *wire.Session) {
	const (
		fetchRespInterval         = 1 * time.Second
		fetchMoreInterval         = 0 * time.Second
		defaultFetchEmptyInterval = 1 * time.Minute
	)

	c.onConnStatusChange(true)

	closeCh := make(chan interface{})
	defer func() {
		c.onConnStatusChange(false)
		close(closeCh)
	}()

	// Start the peer reader.
	cmdCh := make(chan commands.Command)
	go func() {
		defer close(cmdCh)
		for {
			rawCmd, err := w.RecvCommand()
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				return
			}
			c.retryDelay = 0
			select {
			case cmdCh <- rawCmd:
			case <-closeCh:
				return
			}
		}
	}()

	fetchEmptyInterval := defaultFetchEmptyInterval
	if c.c.cfg.MessagePollInterval > time.Duration(0) {
		fetchEmptyInterval = c.c.cfg.MessagePollInterval
	}

	dispatchOnEmpty := func() error {
		if c.c.cfg.OnEmptyFn != nil {
			if err := c.c.cfg.OnEmptyFn(); err != nil {
				c.log.Debugf("Caller failed to handle MessageEmpty: %v", err)
				return err
			}
		}
		return nil
	}

	var consensusCtx *getConsensusCtx
	defer func() {
		if consensusCtx != nil {
			consensusCtx.replyCh <- ErrNotConnected
		}
	}()

	var fetchDelay time.Duration
	var selectAt time.Time
	adjFetchDelay := func() {
		sendAt := time.Now()
		if deltaT := sendAt.Sub(selectAt); deltaT < fetchDelay {
			fetchDelay = fetchDelay - deltaT
		} else {
			fetchDelay = 0
		}
	}
	var seq uint32
	nrReqs, nrResps := 0, 0
	for {
		var rawCmd commands.Command
		var doFetch, ok bool
		selectAt = time.Now()
		select {
		case <-time.After(fetchDelay):
			doFetch = true
		case <-c.fetchCh:
			doFetch = true
		case ctx := <-c.getConsensusCh:
			c.log.Debugf("Dequeued GetConsesus for send.")
			if consensusCtx != nil {
				ctx.doneFn(fmt.Errorf("outstanding GetConsensus already exists: %v", consensusCtx.epoch))
			} else {
				consensusCtx = ctx
				cmd := &commands.GetConsensus{
					Epoch: ctx.epoch,
				}
				err := w.SendCommand(cmd)
				ctx.doneFn(err)
				if err != nil {
					c.log.Debugf("Failed to send GetConsensus: %v", err)
					return
				}
				c.log.Debugf("Send GetConsensus.")
			}

			adjFetchDelay()
			continue
		case ctx := <-c.sendCh:
			c.log.Debugf("Dequeued packet for send.")
			cmd := &commands.SendPacket{
				SphinxPacket: ctx.pkt,
			}
			err := w.SendCommand(cmd)
			ctx.doneFn(err)
			if err != nil {
				c.log.Debugf("Failed to send SendPacket: %v", err)
				return
			}
			c.log.Debugf("Send SendPacket.")

			adjFetchDelay()
			continue
		case rawCmd, ok = <-cmdCh:
			if !ok {
				return
			}
		case <-c.HaltCh():
			return
		}

		// Send a fetch if there is not one outstanding.
		if doFetch {
			if nrReqs == nrResps {
				cmd := &commands.RetrieveMessage{
					Sequence: seq,
				}
				if err := w.SendCommand(cmd); err != nil {
					c.log.Debugf("Failed to send RetrieveMessage: %v", err)
					return
				}
				c.log.Debugf("Sent RetrieveMessage: %d", seq)
				nrReqs++
				fetchDelay = fetchRespInterval
			}
			continue
		}

		// Update the cached descriptor, and re-validate the connection.
		if !c.IsPeerValid(w.PeerCredentials()) {
			c.log.Warningf("No longer have a descriptor for current peer.")
			return
		}

		// Handle the response.
		switch cmd := rawCmd.(type) {
		case *commands.NoOp:
			c.log.Debugf("Received NoOp.")
		case *commands.Disconnect:
			c.log.Debugf("Received Disconnect.")
			return
		case *commands.MessageEmpty:
			c.log.Debugf("Received MessageEmpty: %v", cmd.Sequence)
			if seq != cmd.Sequence {
				c.log.Errorf("MessageEmpty sequence unexpected: %v", cmd.Sequence)
				return
			}
			nrResps++
			fetchDelay = fetchEmptyInterval

			if err := dispatchOnEmpty(); err != nil {
				return
			}
		case *commands.Message:
			c.log.Debugf("Received Message: %v", cmd.Sequence)
			if seq != cmd.Sequence {
				c.log.Errorf("Message sequence unexpected: %v", cmd.Sequence)
				return
			}
			nrResps++
			if c.c.cfg.OnMessageFn != nil {
				if err := c.c.cfg.OnMessageFn(cmd.Payload); err != nil {
					c.log.Debugf("Caller failed to handle Message: %v", err)
					return
				}
			}
			seq++

			// This behavior is only valid assuming the consumers of
			// this library correctly implement persistent de-duplication
			// properly, as is documented in the `OnMessageFn` callback
			// doc string, but the behavior is better on the network.
			if cmd.QueueSizeHint != 0 {
				c.log.Debugf("QueueSizeHint indicates non-empty queue, accelerating next fetch.")
				fetchDelay = fetchMoreInterval
			} else {
				// If the QueueSizeHint is 0, then treat the remote queue as
				// empty, including dispatching the callback if set.
				c.log.Debugf("QueueSizeHint indicates empty queue, delaying next fetch.")
				fetchDelay = fetchEmptyInterval
				if err := dispatchOnEmpty(); err != nil {
					return
				}
			}
		case *commands.MessageACK:
			c.log.Debugf("Received MessageACK: %v", cmd.Sequence)
			if seq != cmd.Sequence {
				c.log.Errorf("MessageACK sequence unexpected: %v", cmd.Sequence)
				return
			}
			nrResps++
			if c.c.cfg.OnACKFn != nil {
				if err := c.c.cfg.OnACKFn(&cmd.ID, cmd.Payload); err != nil {
					c.log.Debugf("Caller failed to handle MessageACK: %v", err)
					return
				}
			}
			seq++

			fetchDelay = fetchMoreInterval // Likewise as with Message...
		case *commands.Consensus:
			if consensusCtx != nil {
				c.log.Debugf("Received Consensus: ErrorCode: %v, Payload %v bytes", cmd.ErrorCode, len(cmd.Payload))
				consensusCtx.replyCh <- cmd
				consensusCtx = nil
			} else {
				// Spurious Consensus replies are a protocol violation.
				c.log.Errorf("Received spurious Consensus.")
				return
			}
		default:
			c.log.Errorf("Received unexpected command: %T", cmd)
			return
		}
	}
}

func (c *connection) IsPeerValid(creds *wire.PeerCredentials) bool {
	// Refresh the cached Provider descriptor.
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

func (c *connection) onConnStatusChange(isConnected bool) {
	c.Lock()
	c.isConnected = isConnected
	if !isConnected {
		// Force drain the channels used to poke the loop.
		select {
		case ctx := <-c.sendCh:
			ctx.doneFn(ErrNotConnected)
		default:
		}
		select {
		case ctx := <-c.getConsensusCh:
			ctx.doneFn(ErrNotConnected)
		default:
		}
		select {
		case <-c.fetchCh:
		default:
		}
	}
	c.Unlock()

	if c.c.cfg.OnConnFn != nil {
		c.c.cfg.OnConnFn(c.isConnected)
	}
}

func (c *connection) sendPacket(pkt []byte) error {
	c.Lock()
	if !c.isConnected {
		c.Unlock()
		return ErrNotConnected
	}

	errCh := make(chan error)
	c.sendCh <- &connSendCtx{
		pkt: pkt,
		doneFn: func(err error) {
			errCh <- err
		},
	}
	c.log.Debugf("Enqueued packet for send.")

	// Release the lock so this won't deadlock in onConnStatusChange.
	c.Unlock()

	return <-errCh
}

func (c *connection) getConsensus(ctx context.Context, epoch uint64) (*commands.Consensus, error) {
	c.Lock()
	if !c.isConnected {
		c.Unlock()
		return nil, ErrNotConnected
	}

	errCh := make(chan error)
	replyCh := make(chan interface{})
	c.getConsensusCh <- &getConsensusCtx{
		replyCh: replyCh,
		epoch:   epoch,
		doneFn: func(err error) {
			errCh <- err
		},
	}
	c.log.Debug("Enqueued GetConsensus command for send.")

	// Release the lock so this won't deadlock in onConnStatusChange.
	c.Unlock()

	// Ensure the dispatch succeeded.
	err := <-errCh
	if err != nil {
		c.log.Debugf("Failed to dispatch GetConsensus: %v", err)
		return nil, err
	}

	// Wait for the dispatch to complete.
	select {
	case rawResp := <-replyCh:
		switch resp := rawResp.(type) {
		case error:
			return nil, resp
		case *commands.Consensus:
			return resp, nil
		default:
			panic("BUG: Worker returned invalid Consensus response")
		}
	case <-ctx.Done():
		// Canceled mid-fetch.
		return nil, errGetConsensusCanceled
	}

	// NOTREACHED
}

func newConnection(c *Client) *connection {
	k := new(connection)
	k.c = c
	k.log = c.cfg.LogBackend.GetLogger("minclient/conn:" + c.displayName)
	k.pkiFetchCh = make(chan interface{}, 1)
	k.fetchCh = make(chan interface{}, 1)
	k.sendCh = make(chan *connSendCtx)
	k.getConsensusCh = make(chan *getConsensusCtx)

	k.Go(k.connectWorker)
	return k
}
